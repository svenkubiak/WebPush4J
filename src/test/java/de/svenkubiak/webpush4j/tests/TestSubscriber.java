package de.svenkubiak.webpush4j.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import de.svenkubiak.webpush4j.exceptions.WebPushException;
import de.svenkubiak.webpush4j.models.Subscriber;

class TestSubscriber {
    private String json = """
                        {
              "endpoint": "https://web.push.apple.com/loreipsum",
              "keys": {
                "p256dh": "loreipsump256dh",
                "auth": "loreipsumgauth"
              }
            }
                        """;
    
    @Test
    void testFrom() {
        //When
        Subscriber subscriber = Subscriber.from(json);
        
        //Then
        assertEquals(subscriber.getEndpoint(), "https://web.push.apple.com/loreipsum");
        assertEquals(subscriber.getP256dh(), "loreipsump256dh");
        assertEquals(subscriber.getAuth(), "loreipsumgauth");
    }
    
    @Test
    void testConstruct() {
        //When
        Subscriber subscriber = new Subscriber("https://web.push.apple.com/loreipsum", "loreipsump256dh", "loreipsumgauth");
        
        //Then
        assertEquals(subscriber.getEndpoint(), "https://web.push.apple.com/loreipsum");
        assertEquals(subscriber.getP256dh(), "loreipsump256dh");
        assertEquals(subscriber.getAuth(), "loreipsumgauth");
    }
    
    @Test
    void testOrigin() throws WebPushException {
        //When
        Subscriber subscriber = new Subscriber("https://fcm.googleapis.com/fcm/send/loreipsum", "loreipsump256dh", "loreipsumgauth");
        
        //Then
        assertEquals(subscriber.getOrigin(), "https://fcm.googleapis.com");
    }
}