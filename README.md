WebPush4J
================

Refactored and improved version of [WebPush](https://github.com/web-push-libs/webpush-java)

- Updated dependencies
- OkHttp instead of httpcomponents
- Reduced code, cleanups and refactorings
- Fluent API

Status: Early development.

Requires Java 17.

Usage
------------------

Add the WebPush4J dependency to your pom.xml:

```
<dependency>
    <groupId>de.svenkubiak</groupId>
    <artifactId>webpush4j</artifactId>
    <version>x.x.x</version>
</dependency>
```

Start by setting up the WebPush instance

```
Security.addProvider(new BouncyCastleProvider());
WebPush webPush = WebPush.crerate()
  .withPublicKey("PUBLIC KEY")
  .withPrivateKey("PRIVATE KEY")
  .withSubject("SUBJECT");
```	

Load or create a Subscriber

```
String json = ... //Json from initial subscription
Subscriber subscriber = Subscriber.from(json);
```	

Create a notification

```
Notification notification = Notification.create()
	.to(subscriber)
  	.withPayload(json);
```	

Send the notification

```
try {
    webPush.send(notification);
} catch (GeneralSecurityException | IOException | JoseException e) {
    //
}
```	