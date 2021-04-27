# XML External Entities \(XXE\)

Extensible Markup Language \(XML\) developed alongside HTML as a more formal markup language. It had the benefit of using a structure that could be defined and validated using a schema definition \(XSD\). This came at the cost of complexity and verbosity, ultimately limiting XML’s popularity. XML pops up quite frequently, Microsoft Office uses an Open XML format for its document types for example. One of the most prevalent vulnerabilities in XML document processing has been XXE. Within XML, an entity is a label for representing text. An example is the entity “&gt;” that is used to represent “&gt;”. To add an entity to an XML document, you declare it in a DTD \(Document Type Defintion\) statement. An example of this would be:

```markup
<!Entity msg "Hello World">  
<email>  
   <to>Jane Doe</to>  
   <body>&msg;</body>  
</email> 
```

The entity definition of “msg” is refered to as “&msg;”.

External entity allowed for entity definitions to be stored in a file remotely and that could be included either through https:// or the file:// protocol. An example of an XXE injection attack exploiting this would be:

```markup
<!DOCTYPE FakeTag [
<!ELEMENT FakeTag ANY >
<!ENTITY ext SYSTEM "file://etc/passwd" >]>
<FakeTag>&ext;</FakeTag>
```

This would include the file /etc/passwd into the text of the response.

XXE can also be used to do a Server Side Request Forgery \(SSRF\). Many internal web applications limit requests from within the perimeter of the internal network. If the request comes from XXE that is fetched by a web server, it may be trusted by these web servers.

