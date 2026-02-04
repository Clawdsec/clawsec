/**
 * Standalone HTTP Proxy Server
 * HTTP server that intercepts and analyzes tool calls without OpenClaw integration
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { ProxyConfig, ProxyServer } from './types.js';
import { AnalysisMiddleware, ValidationError, createAnalysisMiddleware } from './middleware.js';
import { HybridAnalyzer } from '../engine/analyzer.js';
import { InMemoryApprovalStore, createApprovalStore } from '../approval/store.js';

/** Default host to bind to */
const DEFAULT_HOST = '127.0.0.1';

/** Default approval timeout in seconds */
const DEFAULT_APPROVAL_TIMEOUT = 300;

/**
 * Parse JSON body from request
 */
async function parseJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf-8');
      if (!body || body.trim() === '') {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

/**
 * Send JSON response
 */
function sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(data));
}

/**
 * Send error response
 */
function sendError(res: ServerResponse, statusCode: number, message: string): void {
  sendJson(res, statusCode, { error: true, message, statusCode });
}

/**
 * Extract path parameter from URL pattern
 * Example: extractParam('/approve/:id', '/approve/abc123') returns 'abc123'
 */
function extractParam(pattern: string, url: string): string | null {
  const patternParts = pattern.split('/');
  const urlParts = url.split('?')[0].split('/');

  if (patternParts.length !== urlParts.length) {
    return null;
  }

  for (let i = 0; i < patternParts.length; i++) {
    const patternPart = patternParts[i];
    if (patternPart.startsWith(':')) {
      return urlParts[i];
    }
    if (patternPart !== urlParts[i]) {
      return null;
    }
  }

  return null;
}

/**
 * Check if URL matches a pattern
 */
function matchesPattern(pattern: string, url: string): boolean {
  const urlPath = url.split('?')[0];
  const patternParts = pattern.split('/');
  const urlParts = urlPath.split('/');

  if (patternParts.length !== urlParts.length) {
    return false;
  }

  for (let i = 0; i < patternParts.length; i++) {
    const patternPart = patternParts[i];
    if (patternPart.startsWith(':')) {
      continue; // Parameter placeholder matches anything
    }
    if (patternPart !== urlParts[i]) {
      return false;
    }
  }

  return true;
}

/**
 * HTTP Proxy Server Implementation
 */
export class HttpProxyServer implements ProxyServer {
  private readonly config: ProxyConfig;
  private readonly middleware: AnalysisMiddleware;
  private readonly approvalStore: InMemoryApprovalStore;
  private server: Server | null = null;
  private actualPort: number = 0;

  constructor(config: ProxyConfig) {
    this.config = config;

    // Create approval store
    this.approvalStore = createApprovalStore({
      cleanupIntervalMs: 60_000, // Cleanup every minute
      removeOnExpiry: true,
    });

    // Create analyzer
    const analyzer = new HybridAnalyzer({ config: config.clawsecConfig });

    // Get approval timeout from config
    const approvalTimeout = config.clawsecConfig.approval?.native?.timeout ?? DEFAULT_APPROVAL_TIMEOUT;

    // Create middleware
    this.middleware = createAnalysisMiddleware(analyzer, this.approvalStore, approvalTimeout);
  }

  /**
   * Start the server
   */
  async start(): Promise<void> {
    if (this.server) {
      throw new Error('Server already started');
    }

    const host = this.config.host ?? DEFAULT_HOST;
    const port = this.config.port;

    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch((error) => {
          console.error('Unhandled error in request handler:', error);
          sendError(res, 500, 'Internal server error');
        });
      });

      this.server.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'EADDRINUSE') {
          reject(new Error(`Port ${port} is already in use`));
        } else {
          reject(error);
        }
      });

      this.server.listen(port, host, () => {
        const address = this.server?.address();
        if (address && typeof address === 'object') {
          this.actualPort = address.port;
        } else {
          this.actualPort = port;
        }
        resolve();
      });
    });
  }

  /**
   * Stop the server
   */
  async stop(): Promise<void> {
    if (!this.server) {
      return;
    }

    return new Promise((resolve, reject) => {
      // Stop the approval store cleanup timer
      this.approvalStore.stopCleanupTimer();
      this.approvalStore.clear();

      this.server!.close((error) => {
        if (error) {
          reject(error);
        } else {
          this.server = null;
          this.actualPort = 0;
          resolve();
        }
      });
    });
  }

  /**
   * Get the port the server is listening on
   */
  getPort(): number {
    return this.actualPort;
  }

  /**
   * Handle incoming HTTP request
   */
  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method?.toUpperCase() ?? 'GET';
    const url = req.url ?? '/';

    // Set CORS headers for all responses
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    // Route the request
    try {
      // POST /analyze
      if (method === 'POST' && url === '/analyze') {
        await this.handleAnalyze(req, res);
        return;
      }

      // POST /approve/:id
      if (method === 'POST' && matchesPattern('/approve/:id', url)) {
        const id = extractParam('/approve/:id', url);
        if (id) {
          await this.handleApprove(id, res);
          return;
        }
      }

      // POST /deny/:id
      if (method === 'POST' && matchesPattern('/deny/:id', url)) {
        const id = extractParam('/deny/:id', url);
        if (id) {
          await this.handleDeny(id, res);
          return;
        }
      }

      // GET /status
      if (method === 'GET' && url === '/status') {
        this.handleStatus(res);
        return;
      }

      // GET /health
      if (method === 'GET' && url === '/health') {
        this.handleHealth(res);
        return;
      }

      // Not found
      sendError(res, 404, `Not found: ${method} ${url}`);
    } catch (error) {
      if (error instanceof ValidationError) {
        sendError(res, 400, error.message);
      } else if (error instanceof Error) {
        if (error.message === 'Invalid JSON') {
          sendError(res, 400, 'Invalid JSON in request body');
        } else {
          console.error('Request handler error:', error);
          sendError(res, 500, 'Internal server error');
        }
      } else {
        console.error('Unknown error:', error);
        sendError(res, 500, 'Internal server error');
      }
    }
  }

  /**
   * Handle POST /analyze
   */
  private async handleAnalyze(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await parseJsonBody(req);
    const response = await this.middleware.analyze(body as Record<string, unknown>);
    sendJson(res, 200, response);
  }

  /**
   * Handle POST /approve/:id
   */
  private async handleApprove(id: string, res: ServerResponse): Promise<void> {
    const response = this.middleware.approve(id);
    const statusCode = response.success ? 200 : 404;
    sendJson(res, statusCode, response);
  }

  /**
   * Handle POST /deny/:id
   */
  private async handleDeny(id: string, res: ServerResponse): Promise<void> {
    const response = this.middleware.deny(id);
    const statusCode = response.success ? 200 : 404;
    sendJson(res, statusCode, response);
  }

  /**
   * Handle GET /status
   */
  private handleStatus(res: ServerResponse): void {
    const response = this.middleware.getStatus(this.config, this.actualPort);
    sendJson(res, 200, response);
  }

  /**
   * Handle GET /health
   */
  private handleHealth(res: ServerResponse): void {
    const response = this.middleware.getHealth();
    sendJson(res, 200, response);
  }
}

/**
 * Create a proxy server instance
 */
export function createProxyServer(config: ProxyConfig): ProxyServer {
  return new HttpProxyServer(config);
}
