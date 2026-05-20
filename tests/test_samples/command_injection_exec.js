// Test: Command Injection (CWE-78)
// Expected: DETECTED at line 4
var dir = req.query.dir;
exec("ls " + dir);
