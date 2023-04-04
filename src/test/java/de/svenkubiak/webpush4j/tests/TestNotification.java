package de.svenkubiak.webpush4j.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import de.svenkubiak.webpush4j.enums.Dir;
import de.svenkubiak.webpush4j.enums.Urgency;
import de.svenkubiak.webpush4j.models.Notification;

class TestNotification {

    @Test
    void testConstruct() {
        //Given
        Dir dir = Dir.LTR;
        String lang = UUID.randomUUID().toString();
        String icon = UUID.randomUUID().toString();
        String data = UUID.randomUUID().toString();
        String topic = UUID.randomUUID().toString();
        String body = UUID.randomUUID().toString();
        String title = UUID.randomUUID().toString();
        Urgency urgency = Urgency.HIGH;
        long ttl = 23;
        
        //When
        Notification notification = Notification.create()
                .withTitle(title)
                .withTopic(topic)
                .withData(data)
                .withLang(lang)
                .withDir(dir)
                .withIcon(icon)
                .withUrgency(urgency)
                .withBody(body)
                .withTtl(ttl, TimeUnit.DAYS);
        
        //Then
        assertEquals(notification.getTopic(), topic);
        assertEquals(notification.getUrgency(), urgency);
        assertEquals(notification.getTtl(), 1987200);
        assertEquals(notification.getPayload("body"), body);
        assertEquals(notification.getPayload("title"), title);
        assertEquals(notification.getPayload("data"), data);
        assertEquals(notification.getPayload("icon"), icon);
        assertEquals(notification.getPayload("lang"), lang);
        assertEquals(notification.getPayload("dir"), dir.getValue());
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
