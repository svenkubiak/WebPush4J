[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.svenkubiak/webpush4j/badge.svg)](https://mvnrepository.com/artifact/de.svenkubiak/webpush4j)

WebPush4J
================

Refactored and improved version of [WebPush](https://github.com/web-push-libs/webpush-java)

- Switch from Gradle to Maven
- Updated dependencies
- OkHttp instead of httpcomponents
- Reduced code, cleanups and refactorings
- Fluent API
- Requires Java 17

Usage
------------------

1. Add the WebPush4J dependency to your pom.xml:

```xml
<dependency>
    <groupId>de.svenkubiak</groupId>
    <artifactId>webpush4j</artifactId>
    <version>x.x.x</version>
</dependency>
```

2. Create a Subscriber or load from e.g. database

```java
String json = ... //Json from initial subscription
Subscriber subscriber = Subscriber.from(json);
```	

3. Create a notification

```java
Notification notification = Notification.create()
    .withTitle("Hello!!")
    .withBody("New Message from your favorite Server.");
```	

4. Send the notification to the subscriber

Synchronous

```java
try {
    WebPush.crerate()
		.withPublicKey("PUBLIC KEY") //Vapid public key
 		.withPrivateKey("PRIVATE KEY") //Vapid private key
  		.withSubject("SUBJECT");
        	.withSubscriber(subscriber)
        	.withNotification(notification)
        	.send();
} catch (WebPushException e) {
    e.printStackTrace();
}
```	


Full example
------------------

```java
import de.svenkubiak.webpush4j.Notification;
import de.svenkubiak.webpush4j.Subscriber;
import de.svenkubiak.webpush4j.WebPush;
import de.svenkubiak.webpush4j.exceptions.WebPushException;

public class Main {
    public static void main(String... args) {
        Subscriber subscriber = Subscriber.from(json);
                
        Notification notification = Notification.create()
            .withTitle("Hello!!")
            .withBody("New Message from your favorite Server.");
        
        try {
	    WebPush.crerate()
			.withPublicKey("PUBLIC KEY") //Vapid public key
	 		.withPrivateKey("PRIVATE KEY") //Vapid private key
	  		.withSubject("SUBJECT");
	        	.withSubscriber(subscriber)
	        	.withNotification(notification)
	        	.send();
        } catch (WebPushException e) {
            e.printStackTrace();
        }
    }
}

```	