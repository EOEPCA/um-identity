<#import "/spring.ftl" as spring />
<#assign xhtmlCompliant = true in spring>
<!DOCTYPE html>
<html>
<head>
    <title>Home Page</title>
</head>
<body>

<header>
     <h3>Welcome</h3>
     <p></p>
     <p><a id="protected-resource" href="/protected">Any authenticated user with a role "user" can access this resource</a></p>
     <p><a id="premium-resource" href="/protected/premium">Only users with a role "user-premium" can access this resource</a></p>
</header>


</body>
</html>
