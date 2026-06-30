// Test 1: Direct source → sink (should flag)
var input = location.search;
eval(input);

// Test 2: Source through reassignment chain (should flag)
var a = req.body;
var b = a;
setTimeout("Adel", 1000);

window["eval"].apply;

// Test 3: Clean literal → sink (should NOT flag)
eval("console.log('safe')");

// Test 4: Object property with tainted value (should flag property)
var cookie = document.cookie;
var obj = { dangerouslySetInnerHTML: cookie };

// Test 5: document.write with direct source (should flag)
document.write(document.referrer);

// Test 6: Compound expression containing tainted var (should flag)
var userHash = location.hash;
var payload = "prefix" + userHash;
eval(payload);

// Test 7: Sink used as identifier (should track)
var fn = eval;

// Test 8: Clean variable → sink (should NOT flag)
var safe = "hello world";
eval(safe);

// Test 9: Multiple tainted args in one call
var q = req.query;
var p = req.params;
setTimeout(q, p);

// Test 10: Nested member access source → exec sink
var cmd = req.body;
exec(cmd);

// Test 11: bla bla bla
var x = eval;

updateUI(input);

console.log("hello");

x(input);

var y = x;

y(input);

location = input;

var w = window;

// Test 12: postMessage missing sink
w.postMessage(input, "*");

// Test 13: window.open missing sink
w.open(input);

// Test 14: Global Scope Pollution
w[input] = "something";

// Test 15: Aliased uninvoked sink
var e = w["eval"];
e(input);

// Test 16: False Positive Literal Call
setTimeout("FIXED", 50000);

// Test 17: False Positive Fixed Assignment
location = "FIXED location";

function trackSearch(query) {
  document.write(
    '<img src="/resources/images/tracker.gif?searchTerms=' + query + '">',
  );
}
var query = new URLSearchParams(window.location.search).get("search");
if (query) {
  trackSearch(query);
}


document.innerHTML = location;