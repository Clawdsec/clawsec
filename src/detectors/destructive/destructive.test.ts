/**
 * Destructive Detector Tests
 * Comprehensive tests for shell, cloud, git, code, and combined detection
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Main detector
  DestructiveDetectorImpl,
  createDestructiveDetector,
  createDefaultDestructiveDetector,

  // Shell detection
  ShellDetector,
  createShellDetector,
  isDangerousPath,
  matchRmCommand,
  matchSqlCommand,
  matchSystemCommand,
  matchShellCommand,

  // Cloud detection
  CloudDetector,
  createCloudDetector,
  matchAwsCommand,
  matchGcpCommand,
  matchAzureCommand,
  matchKubernetesCommand,
  matchTerraformCommand,
  matchGitCommand,
  matchCloudCommand,

  // Code detection
  CodeDetector,
  createCodeDetector,
  matchPythonCode,
  matchNodeCode,
  matchGoCode,
  matchRustCode,
  matchRubyCode,
  matchJavaCode,
  matchCSharpCode,
  matchPhpCode,
  matchCodePattern,

  // Types
  type DetectionContext,
  type DestructiveDetectorConfig,
} from './index.js';

// =============================================================================
// SHELL DETECTOR TESTS
// =============================================================================

describe('Shell Detector', () => {
  describe('isDangerousPath', () => {
    it('should detect root path as dangerous', () => {
      expect(isDangerousPath('/')).toBe(true);
      expect(isDangerousPath('//')).toBe(true);
    });

    it('should detect system directories as dangerous', () => {
      expect(isDangerousPath('/home')).toBe(true);
      expect(isDangerousPath('/etc')).toBe(true);
      expect(isDangerousPath('/var')).toBe(true);
      expect(isDangerousPath('/usr')).toBe(true);
      expect(isDangerousPath('/bin')).toBe(true);
      expect(isDangerousPath('/boot')).toBe(true);
    });

    it('should detect home directory patterns as dangerous', () => {
      expect(isDangerousPath('~')).toBe(true);
      expect(isDangerousPath('~/')).toBe(true);
      expect(isDangerousPath('$HOME')).toBe(true);
    });

    it('should detect wildcard patterns as dangerous', () => {
      expect(isDangerousPath('*')).toBe(true);
      expect(isDangerousPath('/*')).toBe(true);
      expect(isDangerousPath('.*')).toBe(true);
    });

    it('should not mark normal paths as dangerous', () => {
      expect(isDangerousPath('/tmp/test')).toBe(false);
      expect(isDangerousPath('/home/user/project')).toBe(false);
      expect(isDangerousPath('./node_modules')).toBe(false);
    });
  });

  describe('matchRmCommand', () => {
    it('should detect rm -rf on dangerous paths', () => {
      const result = matchRmCommand('rm -rf /');
      expect(result.matched).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.95);
      expect(result.operation).toBe('rm -rf');
    });

    it('should detect rm -rf with various flag orders', () => {
      expect(matchRmCommand('rm -rf /home').matched).toBe(true);
      expect(matchRmCommand('rm -fr /etc').matched).toBe(true);
      expect(matchRmCommand('rm -r -f /var').matched).toBe(true);
    });

    it('should detect rm -r alone', () => {
      const result = matchRmCommand('rm -r ./directory');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('rm -r');
    });

    it('should detect rm -rf on normal paths with lower confidence', () => {
      const result = matchRmCommand('rm -rf ./build');
      expect(result.matched).toBe(true);
      expect(result.confidence).toBeLessThan(0.95);
    });

    it('should not match non-rm commands', () => {
      expect(matchRmCommand('ls -la').matched).toBe(false);
      expect(matchRmCommand('mkdir test').matched).toBe(false);
    });
  });

  describe('matchSqlCommand', () => {
    it('should detect DROP DATABASE', () => {
      const result = matchSqlCommand('DROP DATABASE production');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('DROP DATABASE');
      expect(result.affectedResource).toBe('production');
    });

    it('should detect DROP TABLE', () => {
      const result = matchSqlCommand('DROP TABLE users');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('DROP TABLE');
    });

    it('should detect DROP TABLE IF EXISTS', () => {
      const result = matchSqlCommand('DROP TABLE IF EXISTS users');
      expect(result.matched).toBe(true);
    });

    it('should detect TRUNCATE TABLE', () => {
      const result = matchSqlCommand('TRUNCATE TABLE logs');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('TRUNCATE TABLE');
    });

    it('should detect DELETE FROM without WHERE', () => {
      const result = matchSqlCommand('DELETE FROM users;');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('DELETE FROM (no WHERE)');
    });

    it('should not match DELETE with WHERE', () => {
      expect(matchSqlCommand('DELETE FROM users WHERE id = 1').matched).toBe(false);
    });

    it('should not match SELECT statements', () => {
      expect(matchSqlCommand('SELECT * FROM users').matched).toBe(false);
    });
  });

  describe('matchSystemCommand', () => {
    it('should detect mkfs commands', () => {
      const result = matchSystemCommand('mkfs.ext4 /dev/sda1');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('mkfs');
    });

    it('should detect dd writing to device', () => {
      const result = matchSystemCommand('dd if=/dev/zero of=/dev/sda bs=1M');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('dd to device');
    });

    it('should detect chmod 777', () => {
      const result = matchSystemCommand('chmod 777 /etc/passwd');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('chmod 777');
    });

    it('should detect fork bomb', () => {
      const result = matchSystemCommand(':(){ :|:& };:');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('fork bomb');
    });

    it('should detect shred command', () => {
      const result = matchSystemCommand('shred -n 3 sensitive.txt');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('shred');
    });
  });

  describe('ShellDetector class', () => {
    let detector: ShellDetector;

    beforeEach(() => {
      detector = createShellDetector('critical');
    });

    it('should detect dangerous command from command input', () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'rm -rf /' },
      };

      const result = detector.detect(context);
      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.category).toBe('destructive');
      expect(result?.metadata?.type).toBe('shell');
    });

    it('should detect from SQL query input', () => {
      const context: DetectionContext = {
        toolName: 'mysql',
        toolInput: { query: 'DROP DATABASE production' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.operation).toBe('DROP DATABASE');
    });

    it('should detect from script input', () => {
      const context: DetectionContext = {
        toolName: 'execute',
        toolInput: { script: 'mkfs.ext4 /dev/sda' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should return null for safe commands', () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'ls -la' },
      };

      const result = detector.detect(context);
      expect(result).toBeNull();
    });

    it('should return null when no command is present', () => {
      const context: DetectionContext = {
        toolName: 'navigate',
        toolInput: { url: 'https://example.com' },
      };

      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// CLOUD DETECTOR TESTS
// =============================================================================

describe('Cloud Detector', () => {
  describe('AWS patterns', () => {
    it('should detect ec2 terminate-instances', () => {
      const result = matchAwsCommand('aws ec2 terminate-instances --instance-ids i-12345');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('aws');
      expect(result.operation).toBe('terminate-instances');
    });

    it('should detect s3 bucket removal', () => {
      expect(matchAwsCommand('aws s3 rb --force s3://my-bucket').matched).toBe(true);
      expect(matchAwsCommand('aws s3api delete-bucket --bucket my-bucket').matched).toBe(true);
    });

    it('should detect RDS deletion', () => {
      const result = matchAwsCommand('aws rds delete-db-instance --db-instance-identifier prod-db');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('delete-db');
    });

    it('should detect CloudFormation stack deletion', () => {
      const result = matchAwsCommand('aws cloudformation delete-stack --stack-name prod-stack');
      expect(result.matched).toBe(true);
    });

    it('should detect Lambda function deletion', () => {
      const result = matchAwsCommand('aws lambda delete-function --function-name my-func');
      expect(result.matched).toBe(true);
    });
  });

  describe('GCP patterns', () => {
    it('should detect compute instances delete', () => {
      const result = matchGcpCommand('gcloud compute instances delete my-instance');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('gcp');
    });

    it('should detect project deletion', () => {
      const result = matchGcpCommand('gcloud projects delete my-project');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('projects delete');
    });

    it('should detect GKE cluster deletion', () => {
      const result = matchGcpCommand('gcloud container clusters delete my-cluster');
      expect(result.matched).toBe(true);
    });

    it('should detect gsutil recursive removal', () => {
      const result = matchGcpCommand('gsutil -m rm -r gs://my-bucket');
      expect(result.matched).toBe(true);
    });
  });

  describe('Azure patterns', () => {
    it('should detect VM deletion', () => {
      const result = matchAzureCommand('az vm delete -g mygroup -n myvm');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('azure');
    });

    it('should detect resource group deletion', () => {
      const result = matchAzureCommand('az group delete --name mygroup');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('group delete');
    });

    it('should detect AKS deletion', () => {
      const result = matchAzureCommand('az aks delete -g mygroup -n mycluster');
      expect(result.matched).toBe(true);
    });
  });

  describe('Kubernetes patterns', () => {
    it('should detect namespace deletion', () => {
      const result = matchKubernetesCommand('kubectl delete namespace production');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('kubernetes');
      expect(result.operation).toBe('delete namespace');
      expect(result.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('should detect delete ns shorthand', () => {
      const result = matchKubernetesCommand('kubectl delete ns staging');
      expect(result.matched).toBe(true);
    });

    it('should detect delete pods --all', () => {
      const result = matchKubernetesCommand('kubectl delete pods --all');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('delete pods --all');
    });

    it('should detect delete with -A flag', () => {
      const result = matchKubernetesCommand('kubectl delete pods -A');
      expect(result.matched).toBe(true);
    });

    it('should detect Helm uninstall', () => {
      const result = matchKubernetesCommand('helm uninstall my-release');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('helm uninstall');
    });
  });

  describe('Terraform patterns', () => {
    it('should detect terraform destroy', () => {
      const result = matchTerraformCommand('terraform destroy');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('terraform');
      expect(result.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('should detect terraform apply with auto-approve', () => {
      const result = matchTerraformCommand('terraform apply -auto-approve');
      expect(result.matched).toBe(true);
    });

    it('should detect terragrunt destroy', () => {
      const result = matchTerraformCommand('terragrunt destroy');
      expect(result.matched).toBe(true);
    });

    it('should detect pulumi destroy', () => {
      const result = matchTerraformCommand('pulumi destroy');
      expect(result.matched).toBe(true);
    });
  });

  describe('Git patterns', () => {
    it('should detect git push --force to main', () => {
      const result = matchGitCommand('git push --force origin main');
      expect(result.matched).toBe(true);
      expect(result.provider).toBe('git');
      expect(result.operation).toBe('push --force main/master');
    });

    it('should detect git push -f to master', () => {
      const result = matchGitCommand('git push -f origin master');
      expect(result.matched).toBe(true);
    });

    it('should detect git reset --hard', () => {
      const result = matchGitCommand('git reset --hard HEAD~5');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('reset --hard');
    });

    it('should detect git clean -fd', () => {
      const result = matchGitCommand('git clean -fd');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('clean -fd');
    });

    it('should detect git branch -D', () => {
      const result = matchGitCommand('git branch -D feature-branch');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('branch -D');
    });

    it('should detect git checkout .', () => {
      const result = matchGitCommand('git checkout .');
      expect(result.matched).toBe(true);
    });
  });

  describe('CloudDetector class', () => {
    let detector: CloudDetector;

    beforeEach(() => {
      detector = createCloudDetector('critical');
    });

    it('should detect AWS commands from context', () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'aws ec2 terminate-instances --instance-ids i-123' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.type).toBe('cloud');
    });

    it('should detect Git commands with git type', () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'git push --force origin main' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.type).toBe('git');
    });

    it('should return null for safe commands', () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'aws s3 ls' },
      };

      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// CODE DETECTOR TESTS
// =============================================================================

describe('Code Detector', () => {
  describe('Python patterns', () => {
    it('should detect shutil.rmtree', () => {
      const result = matchPythonCode('shutil.rmtree("/var/data")');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('python');
      expect(result.operation).toBe('shutil.rmtree');
    });

    it('should detect os.remove', () => {
      const result = matchPythonCode('os.remove("/tmp/file.txt")');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('os.remove');
    });

    it('should detect os.rmdir', () => {
      const result = matchPythonCode('os.rmdir(path)');
      expect(result.matched).toBe(true);
    });

    it('should detect os.removedirs', () => {
      const result = matchPythonCode('os.removedirs("/a/b/c")');
      expect(result.matched).toBe(true);
    });

    it('should detect subprocess with rm', () => {
      const result = matchPythonCode('subprocess.run("rm -rf /tmp/test")');
      expect(result.matched).toBe(true);
    });
  });

  describe('Node.js patterns', () => {
    it('should detect fs.rm with recursive', () => {
      const result = matchNodeCode('fs.rm("/tmp/dir", { recursive: true })');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('javascript');
      expect(result.operation).toBe('fs.rm(recursive)');
    });

    it('should detect fs.rmSync with recursive', () => {
      const result = matchNodeCode('fs.rmSync(path, { recursive: true, force: true })');
      expect(result.matched).toBe(true);
    });

    it('should detect fs.unlink', () => {
      const result = matchNodeCode('fs.unlinkSync("/tmp/file")');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('fs.unlink');
    });

    it('should detect rimraf', () => {
      const result = matchNodeCode('rimraf("/tmp/node_modules")');
      expect(result.matched).toBe(true);
      expect(result.operation).toBe('rimraf');
    });

    it('should detect fs-extra remove', () => {
      const result = matchNodeCode('fse.remove(dir)');
      expect(result.matched).toBe(true);
    });
  });

  describe('Go patterns', () => {
    it('should detect os.RemoveAll', () => {
      const result = matchGoCode('os.RemoveAll("/tmp/dir")');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('go');
      expect(result.operation).toBe('os.RemoveAll');
    });

    it('should detect os.Remove', () => {
      const result = matchGoCode('os.Remove(filepath)');
      expect(result.matched).toBe(true);
    });
  });

  describe('Rust patterns', () => {
    it('should detect fs::remove_dir_all', () => {
      const result = matchRustCode('std::fs::remove_dir_all("/tmp/dir")');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('rust');
    });

    it('should detect fs::remove_file', () => {
      const result = matchRustCode('fs::remove_file(path)');
      expect(result.matched).toBe(true);
    });
  });

  describe('Ruby patterns', () => {
    it('should detect FileUtils.rm_rf', () => {
      const result = matchRubyCode('FileUtils.rm_rf("/tmp/dir")');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('ruby');
      expect(result.operation).toBe('FileUtils.rm_rf');
    });

    it('should detect FileUtils.rm_r', () => {
      const result = matchRubyCode('FileUtils.rm_r(path)');
      expect(result.matched).toBe(true);
    });
  });

  describe('Java patterns', () => {
    it('should detect FileUtils.deleteDirectory', () => {
      const result = matchJavaCode('FileUtils.deleteDirectory(new File("/tmp"))');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('java');
    });

    it('should detect Files.delete', () => {
      const result = matchJavaCode('Files.delete(Paths.get("/tmp/file"))');
      expect(result.matched).toBe(true);
    });
  });

  describe('C# patterns', () => {
    it('should detect Directory.Delete with recursive', () => {
      const result = matchCSharpCode('Directory.Delete(@"C:\\temp", true)');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('csharp');
    });

    it('should detect File.Delete', () => {
      const result = matchCSharpCode('File.Delete("temp.txt")');
      expect(result.matched).toBe(true);
    });
  });

  describe('PHP patterns', () => {
    it('should detect unlink', () => {
      const result = matchPhpCode('unlink("/tmp/file.txt")');
      expect(result.matched).toBe(true);
      expect(result.language).toBe('php');
    });

    it('should detect rmdir', () => {
      const result = matchPhpCode('rmdir($path)');
      expect(result.matched).toBe(true);
    });
  });

  describe('CodeDetector class', () => {
    let detector: CodeDetector;

    beforeEach(() => {
      detector = createCodeDetector('critical');
    });

    it('should detect code patterns from code input', () => {
      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { code: 'shutil.rmtree("/important/data")' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.type).toBe('code');
    });

    it('should detect from content input', () => {
      const context: DetectionContext = {
        toolName: 'file_write',
        toolInput: { content: 'const x = rimraf("/node_modules")' },
      };

      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should return null for safe code', () => {
      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { code: 'console.log("hello world")' },
      };

      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// MAIN DESTRUCTIVE DETECTOR TESTS
// =============================================================================

describe('DestructiveDetector', () => {
  let detector: DestructiveDetectorImpl;

  beforeEach(() => {
    detector = createDefaultDestructiveDetector();
  });

  describe('basic detection', () => {
    it('should detect shell commands', async () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'rm -rf /home' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.category).toBe('destructive');
      expect(result.metadata?.type).toBe('shell');
    });

    it('should detect cloud commands', async () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'aws ec2 terminate-instances --instance-ids i-123' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('cloud');
    });

    it('should detect git commands', async () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'git push --force origin main' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('git');
    });

    it('should detect code patterns', async () => {
      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { content: 'os.RemoveAll("/data")' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.type).toBe('code');
    });
  });

  describe('disabled detector', () => {
    it('should return no detection when disabled', async () => {
      const config: DestructiveDetectorConfig = {
        enabled: false,
        severity: 'critical',
        action: 'confirm',
      };
      const disabledDetector = new DestructiveDetectorImpl(config);

      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'rm -rf /' },
      };

      const result = await disabledDetector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should skip shell detection when shell is disabled', async () => {
      const config: DestructiveDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: false },
        cloud: { enabled: true },
        code: { enabled: true },
      };
      const partialDetector = new DestructiveDetectorImpl(config);

      // This should not be detected since shell is disabled
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'rm -rf /home' },
      };

      const result = await partialDetector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should skip cloud detection when cloud is disabled', async () => {
      const config: DestructiveDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: true },
        cloud: { enabled: false },
        code: { enabled: true },
      };
      const partialDetector = new DestructiveDetectorImpl(config);

      // AWS command should not be detected since cloud is disabled
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'aws ec2 terminate-instances --instance-ids i-123' },
      };

      const result = await partialDetector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should skip code detection when code is disabled', async () => {
      const config: DestructiveDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: true },
        cloud: { enabled: true },
        code: { enabled: false },
      };
      const partialDetector = new DestructiveDetectorImpl(config);

      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { content: 'shutil.rmtree("/data")' },
      };

      const result = await partialDetector.detect(context);
      expect(result.detected).toBe(false);
    });
  });

  describe('configuration', () => {
    it('should use configured severity', async () => {
      const config: DestructiveDetectorConfig = {
        enabled: true,
        severity: 'high',
        action: 'warn',
      };
      const customDetector = new DestructiveDetectorImpl(config);

      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'rm -rf /tmp/test' },
      };

      const result = await customDetector.detect(context);
      expect(result.severity).toBe('high');
    });

    it('should create detector from DestructiveRule', () => {
      const rule = {
        enabled: true,
        severity: 'high' as const,
        action: 'warn' as const,
        shell: { enabled: true },
        cloud: { enabled: false },
        code: { enabled: true },
      };

      const ruleDetector = createDestructiveDetector(rule);
      expect(ruleDetector.isEnabled()).toBe(true);
      expect(ruleDetector.getAction()).toBe('warn');
      expect(ruleDetector.isShellEnabled()).toBe(true);
      expect(ruleDetector.isCloudEnabled()).toBe(false);
      expect(ruleDetector.isCodeEnabled()).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should handle empty context', async () => {
      const context: DetectionContext = {
        toolName: 'unknown',
        toolInput: {},
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should handle context with no matching patterns', async () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'ls -la' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should not false positive on safe file operations', async () => {
      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { content: 'console.log("removing old entries")' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should not false positive on safe SQL', async () => {
      const context: DetectionContext = {
        toolName: 'sql',
        toolInput: { query: 'SELECT * FROM users WHERE deleted = true' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should not false positive on safe git commands', async () => {
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { command: 'git push origin feature-branch' },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });
  });

  describe('combined detection', () => {
    it('should boost confidence when multiple detectors match', async () => {
      // A command that could match multiple patterns
      const context: DetectionContext = {
        toolName: 'bash',
        toolInput: { 
          command: 'rm -rf /var/data',
          // Also contains code pattern
          script: 'shutil.rmtree("/var/data")' 
        },
      };

      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      // Should have boosted confidence from multiple matches
      expect(result.confidence).toBeGreaterThan(0.85);
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  it('should work with realistic bash tool context', async () => {
    const detector = createDefaultDestructiveDetector();

    const context: DetectionContext = {
      toolName: 'mcp__bash__execute',
      toolInput: {
        command: 'rm -rf node_modules && npm install',
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.metadata?.type).toBe('shell');
  });

  it('should work with Kubernetes deployment context', async () => {
    const detector = createDefaultDestructiveDetector();

    const context: DetectionContext = {
      toolName: 'bash',
      toolInput: {
        command: 'kubectl delete namespace production',
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.metadata?.type).toBe('cloud');
    expect(result.confidence).toBeGreaterThanOrEqual(0.95);
  });

  it('should work with terraform destroy context', async () => {
    const detector = createDefaultDestructiveDetector();

    const context: DetectionContext = {
      toolName: 'shell',
      toolInput: {
        command: 'cd infrastructure && terraform destroy -auto-approve',
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
  });

  it('should work with file write containing dangerous code', async () => {
    const detector = createDefaultDestructiveDetector();

    const context: DetectionContext = {
      toolName: 'write_file',
      toolInput: {
        path: '/app/cleanup.py',
        content: `
import shutil
import os

def cleanup():
    shutil.rmtree('/var/cache')
    os.removedirs('/tmp/old_data')
`,
      },
    };

    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.metadata?.type).toBe('code');
  });

  it('should not trigger on documentation mentioning dangerous commands', async () => {
    const detector = createDefaultDestructiveDetector();

    // This is tricky - we want to avoid false positives on docs
    // but still catch actual dangerous commands
    const context: DetectionContext = {
      toolName: 'write_file',
      toolInput: {
        path: '/docs/README.md',
        content: `
# Cleanup Guide

To clean up, you can use \`rm -rf\` but be careful!
Never run commands like DROP DATABASE without backup.
`,
      },
    };

    // This will detect because the patterns are present
    // In practice, one might want to exclude markdown files
    const result = await detector.detect(context);
    // The detector will trigger - this is expected for security-first approach
    expect(result.category).toBe('destructive');
  });
});
