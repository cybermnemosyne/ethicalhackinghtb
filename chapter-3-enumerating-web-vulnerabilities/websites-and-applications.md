# Websites Vulnerabilities

> In the previous chapter we covered enumeration of a variety of services and introduced the exploration of websites. Websites and web-based applications often represent the largest attack surface of companies because they are by-design externally accessible. At the same time, there has been an increase in the complexity of the code and the number of different components in a website or web application increasing the likelihood of vulnerabilities that can be exploited. In this chapter, we will explore the different categories of the most common serious vulnerabilities known as the OWASP top 10 \(Open Web Application Security Project\) and look at how to enumerate, and exploit, them. In the chapter's exercises, we will cover examples of these classes of vulnerabilities in the machines Bankrobber, JSON, Multimaster, Netmon and ForwardSlash.

Web sites are a collection of files that provide \(static\) formatting instructions as to a browser about how to layout content on a page. This comes in the form of HTML \(Hypertext Markup Language\), CSS \(Cascading Style Sheets\) and media files such as images. Dynamic behavior to add interactivity to a page in the browser can be added via JavaScript. JavaScript can also alter the formatting of a page by interacting with a rendered page's Document Object Model \(DOM\). The DOM is the way the browser organizes the HTML elements that control the formatting of the page.

A web page can communicate with other programs running on servers by submitting data through the use of HTML forms, or by using communications technologies such as Web Sockets and Ajax \(Asynchronous JavaScript and XML\). This communication can be handled using a variety of different programming frameworks and web services including REST \(Representational State Transfer\), Python Django, Ruby on Rails and ASP.NET \(to name just a few of the many\).

Web services that are provided by applications running on servers typically interact with database technologies of some kind to handle the data used by the application. This will be either a relational database of some sort \(some examples of which are MySQL, PostgreSQL, Microsoft SQL Server, Oracle\) or what is called a NoSQL database \(for example, MongoDB, AWS Dynamo DB, Azure Cosmos DB\).

It is the interactivity of web sites and applications that make them vulnerable to exploitation and give attackers the ability to execute commands on the remote machine, or view or alter files on that machine. Although there are many ways in which the interaction of browser, web applications, operating systems and databases can be exploited, we are going to focus on the top 10 most common types of vulnerabilities that are exploited by attackers.

## OWASP Top 10 Web Vulnerabilities

Whilst browsing a website, there are a number of specific types of vulnerabilities that you would be looking for. This starts with identifying the software being used for the site, the directory structure as outlined in the previous chapter, and then concentrating on the functionality of the site.

When looking for vulnerabilities, it is worth concentrating on the most common. The Open Web Application Security Project \(OWASP\) maintains a list of the top 10 most critical security risks to web applications. The latest list is:

1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities \(XXE\)
5. Broken Access Control
6. Security Misconfiguration
7. Cross-Site Scripting \(XSS\)
8. Insecure Deserialisation
9. Using Components with Known Vulnerabilities
10. Insufficient Logging and Monitoring

There are tools which will scan a web application automatically for these vulnerabilities with varying degrees of success. Some of these tools include OWASP ZAP, Burp Suite Professional, OpenVAS and Nessus to name a few. We will be doing the process manually however because it is important to understand the underlying mechanisms by which these vulnerabilities work, and also how they can be mitigated.

We will look at this slightly out of order because I want to cover an example of cross-site scripting XSS that then leads to a SQL injection vulnerability being exposed.

