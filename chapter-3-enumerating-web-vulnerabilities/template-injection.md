# Template Injection



Web application frameworks often use a templating engine which allows them to easily create web pages of html from a combination of html and data. A template file \(sample.html.twig\) using the PHP template system Twig might look like

 &lt;p&gt;

 {{ name }} is a {{ occupation }}

 &lt;/p&gt;

The PHP code to render this as an html page would then be:

echo $twig-&gt;render\('sample.html.twig', \['name' =&gt; 'John Doe',

 'occupation' =&gt; 'Penetration Tester'\]\);

A vulnerability would occur with code that works as follows:

echo $twig-&gt;render\('sample.html.twig', \['name' =&gt; $\_GET\[‘name’\],

 'occupation' =&gt; $\_GET\[‘occupation’\]\]\);

An attacker can detect the injection by passing the string “{{7\*7}}” as the name argument and seeing 49 displayed in the rendered page. For the Python template engine Jinja2, the string ‘{{7\*7}}” produces a different result of “7777777” which enables us to differentiate the underlying code environment.



