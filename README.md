[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.svenkubiak/webpush4j/badge.svg)](https://maven-badges.herokuapp.com/maven-central/de.svenkubiak/webpish4j)

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

1. Add the WebPush4J dependency to your pom.xml:

```
<dependency>
    <groupId>de.svenkubiak</groupId>
    <artifactId>webpush4j</artifactId>
    <version>x.x.x</version>
</dependency>
```

2. Start by creating a WebPush instance

```
WebPush webPush = WebPush.crerate()
  .withPublicKey("PUBLIC KEY") //Vapid public key
  .withPrivateKey("PRIVATE KEY") //Vapid private key
  .withSubject("SUBJECT");
```	

3. Create a Subscriber or load from e.g. database

```
String json = ... //Json from initial subscription
Subscriber subscriber = Subscriber.from(json);
```	

4. Create a notification

```
Notification notification = Notification.create()
    .withTitle("Hello!!")
    .withBody("New Message from your favorite Server.");
```	

5. Send the notification to the subscriber

```
try {
    webPush
        .withSubscriber(subscriber)
        .withNotification(notification)
        .send();
} catch (WebPushException e) {
    e.printStackTrace();
}
```	

Full Example

```
import de.svenkubiak.webpush4j.Notification;
import de.svenkubiak.webpush4j.Subscriber;
import de.svenkubiak.webpush4j.WebPush;
import de.svenkubiak.webpush4j.exceptions.WebPushException;

public class Main {
    public static void main(String... args) {
        WebPush webPush = WebPush.crerate()
                .withPublicKey("PUBLIC KEY")
                .withPrivateKey("PRIVATE KEY")
                .withSubject("SUBJECT");
        
        Subscriber subscriber = Subscriber.from(json);
                
        Notification notification = Notification.create()
            .withTitle("Hello!!")
            .withBody("New Message from your favorite Server.");
        
        try {
            webPush
                .withSubscriber(subscriber)
                .withNotification(notification)
                .send();
        } catch (WebPushException e) {
            e.printStackTrace();
        }
    }
}

```	