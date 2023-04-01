package de.svenkubiak.webpush4j.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import de.svenkubiak.webpush4j.Subscriber;
import de.svenkubiak.webpush4j.exceptions.WebPushException;

public class TestSubscriber {
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
    void testIsFcm() {
        //When
        Subscriber subscriber = new Subscriber("https://android.googleapis.com/gcm/send/loreipsum", "loreipsump256dh", "loreipsumgauth");
        
        //Then
        assertFalse(subscriber.isFcm());
        assertTrue(subscriber.isGcm());
    }
    
    @Test
    void testIsGcm() {
        //When
        Subscriber subscriber = new Subscriber("https://fcm.googleapis.com/fcm/send/loreipsum", "loreipsump256dh", "loreipsumgauth");
        
        //Then
        assertTrue(subscriber.isFcm());
        assertFalse(subscriber.isGcm());
    }
    
    @Test
    void testOrigin() throws WebPushException {
        //When
        Subscriber subscriber = new Subscriber("https://fcm.googleapis.com/fcm/send/loreipsum", "loreipsump256dh", "loreipsumgauth");
        
        //Then
        assertEquals(subscriber.getOrigin(), "https://fcm.googleapis.com");
    }
}