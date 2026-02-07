# POC Testing Instructions

## Goal

Test each step of complexity to identify at what point hooks stop executing on second activation.

## Prerequisites

- OpenClaw installed and configured
- This repository cloned locally
- Terminal access for commands

## Step-by-Step Testing Process

### Setup: Switch to POC Mode

1. **Backup the production plugin manifest:**
   ```bash
   mv openclaw.plugin.json openclaw.plugin.prod.json
   ```

2. **Activate the POC manifest:**
   ```bash
   mv openclaw.plugin.poc.json openclaw.plugin.json
   ```

3. **Build the POC:**
   ```bash
   npm run build:poc
   ```
   This compiles `src/index-poc.ts` → `dist/src/index-poc.js`

4. **Install the POC plugin:**
   ```bash
   openclaw plugins install -l ./
   ```

5. **Verify installation:**
   ```bash
   openclaw plugins list
   # Should show: clawsec-poc (version 1.0.0-poc)
   ```

---

### Test Step 1: Inline Handler (Default)

**What it tests:** Simplest possible hook - inline handler, no closures, no state.

**Current code:** Already active in `src/index-poc.ts` (uncommented)

#### Test Procedure:

1. **First Activation:**
   ```bash
   # Start OpenClaw (or restart if already running)
   openclaw start
   ```

2. **Trigger a tool call:**
   - Use OpenClaw to make ANY agent request that uses a tool
   - Example: Ask agent to "list files in current directory"

3. **Check logs:**
   ```bash
   # Look for POC output in OpenClaw logs
   tail -f ~/.openclaw/logs/openclaw.log  # Adjust path as needed
   ```

4. **Expected output (First Activation):**

   **During plugin load (REGISTRATION PHASE):**
   ```
   ================================================================================
   [POC STEP 1] 📝 REGISTRATION PHASE - register() called
   [POC STEP 1] Timestamp: 2024-XX-XXTXX:XX:XX.XXXZ
   [POC STEP 1] API available: true
   [POC STEP 1] registerHook available: function
   ================================================================================
   [POC STEP 1] ✓ Hook registered with ID: clawsec-poc-hook-step1
   [POC STEP 1] Waiting for tool calls to trigger hook...
   ```

   **When you trigger a tool call (EXECUTION PHASE):**
   ```
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   [POC STEP 1] ✅ EXECUTION PHASE - Hook TRIGGERED!
   [POC STEP 1] Tool name: <tool-name>
   [POC STEP 1] Execution timestamp: 2024-XX-XXTXX:XX:XX.XXXZ
   [POC STEP 1] Session: <session-id>
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ```

   **⚠️ KEY DISTINCTION:**
   - `📝 REGISTRATION PHASE` = Hook being registered (happens once on plugin load)
   - `✅ EXECUTION PHASE - Hook TRIGGERED!` = Hook handler actually running (happens per tool call)
   - We're testing if EXECUTION PHASE logs appear on second activation!

5. **Restart OpenClaw (Second Activation):**
   ```bash
   # Send SIGTERM to OpenClaw process, or use OpenClaw's restart command
   pkill -TERM openclaw
   openclaw start
   ```

6. **Trigger another tool call:**
   - Use OpenClaw again to make ANY tool-using request
   - Same as before: "list files in current directory"

7. **Check logs again:**
   - Do you see `[POC STEP 1] register() called` again?
   - Do you see `[POC STEP 1] ✅ Hook EXECUTED` again?

8. **Document results in POC-RESULTS.md:**
   - ✅ Works on second activation? → Inline handlers are fine
   - ❌ Fails on second activation? → Even inline handlers break

---

### Test Step 2: Handler Factory

**What it tests:** Handler created by factory function (introduces closures).

#### Enable Step 2:

1. **Edit `src/index-poc.ts`:**
   - Comment out Step 1 default export (lines ~60-75)
   - Uncomment Step 2 code (lines ~80-110)

2. **Rebuild:**
   ```bash
   npm run build:poc
   ```

3. **Reinstall:**
   ```bash
   openclaw plugins install -l ./
   ```

#### Test Procedure:

Follow same testing procedure as Step 1, but look for `[POC STEP 2]` logs.

**Key thing to observe:** Do you see DIFFERENT `createdTimestamp` values between first and second activation?

- ✅ Expected: Each activation creates a NEW handler with NEW timestamp
- ❌ Problem: Same timestamp seen on second activation (handler cached)

**Document results in POC-RESULTS.md**

---

### Test Step 3: Module State

**What it tests:** Module-level state variables (singletons).

#### Enable Step 3:

1. **Edit `src/index-poc.ts`:**
   - Comment out Step 2 export
   - Uncomment Step 3 code (lines ~115-160)

2. **Rebuild and reinstall:**
   ```bash
   npm run build:poc
   openclaw plugins install -l ./
   ```

#### Test Procedure:

Follow same testing procedure, look for `[POC STEP 3]` logs.

**Key thing to observe:** Does `activationCount` increment on second activation?

- ✅ Expected: First activation shows `1`, second shows `2` (module reloaded)
- ❌ Problem: Both show `1` (module cached, state persists incorrectly)

**Document results in POC-RESULTS.md**

---

### Test Step 4: Activate/Deactivate Pattern

**What it tests:** The pattern Clawsec currently uses (matches production code).

#### Enable Step 4:

1. **Edit `src/index-poc.ts`:**
   - Comment out Step 3 export
   - Uncomment Step 4 code (lines ~165-250)

2. **Rebuild and reinstall:**
   ```bash
   npm run build:poc
   openclaw plugins install -l ./
   ```

#### Test Procedure:

Follow same testing procedure, look for `[POC STEP 4]` logs.

**Key thing to observe:**

- Does `activate()` get called on second activation?
- Does it skip hook registration due to `state.initialized === true`?
- Does `deactivate()` ever get called between activations?
- Does `activationCount` show the restart happened?

**Expected behavior (if working):**
1. First activation: `initialized: false` → registers hook
2. Restart triggers deactivate → `initialized: false` again
3. Second activation: `initialized: false` → registers hook AGAIN

**Broken behavior:**
1. First activation: `initialized: false` → registers hook
2. Restart does NOT trigger deactivate (or state persists)
3. Second activation: `initialized: true` → SKIPS hook registration

**Document results in POC-RESULTS.md**

---

## Cleanup: Switch Back to Production

After testing all steps:

1. **Restore production manifest:**
   ```bash
   mv openclaw.plugin.json openclaw.plugin.poc.json
   mv openclaw.plugin.prod.json openclaw.plugin.json
   ```

2. **Rebuild production plugin:**
   ```bash
   npm run build
   ```

3. **Reinstall production plugin:**
   ```bash
   openclaw plugins install -l ./
   ```

---

## Troubleshooting

### No logs appear at all

- Check OpenClaw log location: `openclaw config get logDir`
- Try adding `console.error()` in addition to `console.log()` (different streams)
- Verify plugin is installed: `openclaw plugins list`
- Check plugin is enabled: `openclaw plugins info clawsec-poc`

### Logs appear but hooks don't execute

- Verify the tool call actually happened (check OpenClaw agent output)
- Check if hook registration failed (look for error messages)
- Try a different tool (e.g., bash command, file read)

### Can't restart OpenClaw

- Check OpenClaw docs for proper restart procedure
- Try: `openclaw restart` or `openclaw stop && openclaw start`
- If using process manager, use that to restart

### Build errors

- Ensure you're building the POC: `npm run build:poc`
- Check TypeScript errors: `npx tsc --noEmit`
- Verify `src/index-poc.ts` syntax is valid

---

## What to Look For

At each step, answer these questions in `POC-RESULTS.md`:

### Critical Question: Do Hooks Get TRIGGERED on Second Activation?

**Look for these specific logs:**

1. **REGISTRATION PHASE logs** (📝)
   - Do you see `register()` or `activate()` being called on second activation?
   - YES = Module is being reloaded ✅
   - NO = Module is cached, not reloaded ❌

2. **EXECUTION PHASE logs** (✅)
   - Do you see `Hook TRIGGERED!` when you call a tool on second activation?
   - YES = Hook handler is executing, this pattern works! ✅
   - NO = Hook handler NOT executing, this pattern is broken ❌

### Secondary Diagnostic Questions:

3. **What's the last log message you see?**
   - If you see REGISTRATION but not EXECUTION → Hook registered but not triggering
   - If you see neither → Module not reloading at all

4. **Do state values change between activations?**
   - Timestamps, activation counters, etc.
   - Different values = Module reloaded
   - Same values = Module cached incorrectly

5. **Are there any error messages?**
   - Hook registration failures
   - Type errors
   - OpenClaw warnings

### The Ultimate Test:

**On second activation, after triggering a tool call, did you see:**
```
[POC STEP X] ✅ EXECUTION PHASE - Hook TRIGGERED!
```

- ✅ YES = This pattern works on second activation
- ❌ NO = This pattern breaks on second activation

## Next Steps

Once you've identified which step breaks:

1. Document findings in `POC-RESULTS.md`
2. Review the plan's "Step 5: Identify Breaking Point" section
3. Plan the fix for the real implementation (`src/index.ts`)
4. Create a new plan for implementing that fix

**Remember:** Do NOT modify `src/index.ts` yet. We're just diagnosing the problem with POC.
