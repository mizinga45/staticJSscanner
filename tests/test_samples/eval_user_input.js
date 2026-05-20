// Test: Insecure eval() (CWE-95)
// Expected: DETECTED at line 4
var userInput = location.hash;
eval(userInput);
