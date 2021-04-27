# SQL Injection

As mentioned before, web pages running in a browser can interact with a server application on a remote machine by sending instructions and data from the browser using parameters passed in the URL \(called the query string\), HTML forms, or by using JavaScript. The server, receiving instructions and data, will usually use this to complete some functionality, using information stored in a database. An example might be a login screen which takes a username and password in a form and submits them to the server for validation against user information in a database.

An injection vulnerability occurs when an attacker can manipulate the instructions or data collected by a browser before it is sent to the server application. This manipulation consists of injecting commands into the data that get executed and then exploits a number of different areas of functionality provided by the web application, revealing information from the operating system such as viewing and updating files or directly interacting with the database.

Of the main types of injection vulnerabilities in websites, SQL injection \(SQLi\) has been the most prevalent, but other types of injection vulnerabilities can occur, including; NoSQL, Object Relational Mapping \(ORM\), Expression Language \(EL\), Object Graph Navigation Library \(OGNL\) and Template injection.

## SQL Injection

SQL injections occur when a parameter provided from a user as part of a submitted form or action is added, unprocessed, to a query:

```sql
"select * from users where username = '" + request.getParameter("username") + "'"
```

A field expecting a username parameter can be altered by customizing the input

```sql
john' or '1'='1' --
```

This results in a SQL query

```sql
"select * from users where username = 'john' or '1'='1' -- "
```

The query will return all users because the query will always be true. The “--“ characters at the end are comment characters in MySQL SQL and will terminate any further evaluation of the query. How the SQL injection manifests in terms of functional behavior of the application depends on what the input was supposed to do. If it was a username field for a login, the effect will likely be that any username given will be accepted as existing. If the password field is also injectable, then the login process can be bypassed.

This type of SQL injection is known as a “blind injection” because the output of the SQL query is not immediately apparent in a response. In the case of input fields that control the output of information on a page, a search box for example, the entire contents of a database and other databases can be exposed.

Generally when testing for a SQL injection vulnerability, we try and alter the input data to get a change in the returned HTML. Sometimes this might be simply looking at the length of the returned data or having the application return an error because the format is incorrect SQL code.

After working out whether an input is SQL injectable, the next challenge is to craft a SQL statement to return data from any table or database of our choosing. One way of doing this is to use a “Union Select” injection. A union command in SQL allows you to combine the results of two separate select statements. By using a union, we can add our own entirely separate select statement to the existing query and have the results of that query be returned alongside the results of the original query. In order for a union select to work, the number and usually, the type, of columns returned by both queries need to match. The first thing we need to do is to work out how many columns were being returned by the original query. We can do this by using a "order by" keyword. The order by keyword tells the query which column to sort the returned results on. So the the following query of data from a users table will order the returned results by the 2nd column, i.e. the email address:

```sql
select username, email, phone_number from users order by 2;
```

If you specify a number that is greater than the number of columns, the query will fail. To find the number of columns returned by the query, we just need to increase the number until the query fails. Once you have the number of columns returned, you can now create queries where the results are returned in one or more columns, depending on how many, and the types, of the original query's columns. Taking the query we have just detailed and adding a union select to it, we could return the version of a MySQL database by using the injected code:

```sql
john' union select @@version,'john@test.com','12345678'
```

Of course, we would have to terminate the injected SQL appropriately. There are other types of approaches to injection other than union injection and these include time based and error based injections. Error based injections can be used when error information is viewable. The error will contain information about whatever is causing the error and we can use that to return values by deliberately forcing errors to occur. In time based injection, we don't get actual results but we can infer if a query is true or false by the amount of time the query takes to execute.

Fortunately, SQL injection can be done relatively easily without worrying about the details of types of attack, SQL syntax and database idiosyncrasies by using a tool called Sqlmap that can determine the type of database being used and then what injected queries the vulnerability will be susceptible to. With this established, Sqlmap can dump the entire contents of a database or selected tables.

