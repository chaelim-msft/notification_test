# How to create Python Graph Notification WebApp #

----------
## OAuth ##
* [Flow](https://github.com/OfficeDev/microsoft-graph-docs/blob/master/content/authorization/app_authorization.md)

## PPE Environment ##
1. Register app: https://windows.azure-test.net/prepsp.ccsctp.net
    * Go to Active Directory and select Applications Tab
    * Create App and get CLINET_ID and SECRET

* [Creating MSA Apps](https://msft.spoppe.com/sites/Identity/MSODS/_layouts/OneNote.aspx?id=%2Fsites%2FIdentity%2FMSODS%2FSitePages%2FMSODS%20Handbook&wd=target%28Components%2FMSA-AAD%20Convergence.one%7C97D0AD69-FD46-4E42-816B-F8445A135CC1%2FCreating%20MSA%20Applications%7C4DF8D291-389E-4F7F-8FFA-87F7E761840E%2F%29)



## Python Flask ##
~~~
pip install flask
pip install requests
pip install urllib
pip install flask-login
pip install flask-sqlalchemy
~~~


## Subscription Endpoints ##
* PPE: https://graph.microsoft-ppe.com/beta/subscriptions
* TEST: https://graph.microsoft-ppe.com/testNotifications1111/subscriptions 

## Notification API Endpoints ##
* Store:
    * TEST: https://subscriptionstore.cloudapp.net/1.0/ 
    * PPE: https://subscriptionstore-ppe.cloudapp.net/1.0
    * PROD: https://subscriptionstore-prod.cloudapp.net/1.0 
    * https://subscriptionstore.windows.net

* Publisher:
    * TEST: https://publisher.cloudapp.net/1.0/ 
    * PPE: https://publisher-ppe.cloudapp.net/1.0
    * PROD: https://publisher-prod.cloudapp.net/1.0


## End to End testing ##
1. Goto http://notificationstest2.azurewebsites.net/
1. Sign in 
	* For Prod: use one of the tenants here Test Tenants (use the username & password info in the "Users" column). You can also use your own @microsoft.com email , but this may cause to app to receive a lot of notifications depending on the resource you subscribe to and your Outlook activity!
	* For PPE/Test: use billtest account
		* Username: billtest@prepsp.ccsctp.net
2. https://webhookappexample.azurewebsites.net/viewSubscriptions



* [OneBox](http://adbuild/deploy/Topologies_OneBox.aspx)



## Subscription Store Console Testing ##
* Run first instance `SubscriptionStore.Service.Console.exe`
* Other instances `SubscriptionStore.Service.Console.exe /web-`


## (Charlie's DemoApp) WebApp Endpoints ##
* http://notificationstest2.azurewebsites.net/

* NotificationUrl = "https://webhookappexample.azurewebsites.net/api/notifications";

* ServiceEndpoint
    * PROD: https://graph.microsoft.com/{SchemaVersion}/subscriptions
    * TEST/PERF: https://graph.microsoft-ppe.com/{SchemaVersion}/subscriptions

* AuthorityUri 
    * PROD: https://login.windows.net/common/oauth2/authorize?resource=https://graph.microsoft.com/
    * TEST/PERF: https://login.windows-ppe.net/common/oauth2/authorize?resource=https://graph.microsoft-ppe.com/
    

* TokenUrl
    * TEST/PERF: https://login.windows-ppe.net/common/oauth2/token

* See KeePass for ClientId and Secret

* Version
    * PROD: "beta"
    * PPE: "beta"
    * TEST: "testNotifications1111"

* Account: billtest@prepsp.ccsctp.net

* Register app: https://windows.azure-test.net/prepsp.ccsctp.net

* [Creating MSA Apps](https://msft.spoppe.com/sites/Identity/MSODS/_layouts/OneNote.aspx?id=%2Fsites%2FIdentity%2FMSODS%2FSitePages%2FMSODS%20Handbook&wd=target%28Components%2FMSA-AAD%20Convergence.one%7C97D0AD69-FD46-4E42-816B-F8445A135CC1%2FCreating%20MSA%20Applications%7C4DF8D291-389E-4F7F-8FFA-87F7E761840E%2F%29)


manage.windowsazure.com/microsoft.onmicrosoft.com


## Python Test Framework ##
### Flask ###
* [Tutorial](http://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)
### OAuth ###
* [Sample](https://github.com/OfficeDev/O365-Python-Microsoft-Graph-Connect/blob/master/connect/auth_helper.py)
    * [Doc](http://graph.microsoft.io/docs/platform/python)
    * [Walkthrough](https://graph.microsoft.io/docs/platform/rest)
    * [App_authorization](https://github.com/OfficeDev/microsoft-graph-docs/blob/master/content/authorization/app_authorization.md)


http://notificationstest2.azurewebsites.net

https://support.zendesk.com/hc/en-us/articles/206028467-Adding-OAuth-Part-3-Managing-the-authorization-flow
http://getbootstrap.com/getting-started/
http://blog.miguelgrinberg.com/post/oauth-authentication-with-flask

https://flask-login.readthedocs.org/en/latest/
http://flask-sqlalchemy.pocoo.org/2.1/quickstart/#simple-relationships
https://gist.github.com/kemitche/9749639
https://github.com/reddit/reddit/wiki/OAuth2-Python-Example

microblog example https://github.com/joestump/python-oauth2/blob/master/example/client.py

http://douglasstarnes.com/index.php/2015/05/27/easy-authentication-with-flask-login/

https://github.com/douglasstarnes/dscom-flask-login/blob/master/templates/index.html
https://github.com/OfficeDev/microsoft-graph-docs/blob/master/content/authorization/app_authorization.md