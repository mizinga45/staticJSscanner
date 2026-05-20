// Test: SQL Injection (CWE-89)
// Expected: DETECTED at line 4
var userId = req.params.id;
var query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
