package de.svenkubiak.webpush4j.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import de.svenkubiak.webpush4j.enums.Urgency;
import de.svenkubiak.webpush4j.models.Notification;

public class TestNotification {

    @Test
    void testConstruct() {
        //Given
        String topic = UUID.randomUUID().toString();
        Urgency urgency = Urgency.HIGH;
        int ttl = 23;
        
        //When
        Notification notification = Notification.create()
                .withTopic(topic)
                .withUrgency(urgency)
                .withTtl(ttl);
        
        //Then
        assertEquals(notification.getTopic(), topic);
        assertEquals(notification.getUrgency(), urgency);
        assertEquals(notification.getTtl(), ttl);
    }
    
    @Test
    void testPayloadAndUrgencyAndTopic() {
        //Given
        String title = UUID.randomUUID().toString();
        String topic = UUID.randomUUID().toString();
        Urgency urgency = Urgency.HIGH;
        
        //When
        Notification notification = Notification.create();
        
        //Then
        assertFalse(notification.hasPayload());
        assertFalse(notification.hasTopic());
        assertFalse(notification.hasUrgency());
        
        //When
        notification
            .withTitle(title)
            .withTopic(topic)
            .withUrgency(urgency);
        
        //Then
        assertTrue(notification.hasPayload());
        assertTrue(notification.hasTopic());
        assertTrue(notification.hasUrgency());
    }
}
