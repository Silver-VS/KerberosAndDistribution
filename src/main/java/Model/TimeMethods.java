package Model;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

public class TimeMethods {

    public static Timestamp timeSignature(){
        return Timestamp.from(Instant.now());
    }

    public static String timeSignatureInString() {
        return timeSignature().toString();
    }

    public static String timeStamp2String(Timestamp timestamp) {
        return DateTimeFormatter.ISO_DATE_TIME.format(timestamp.toLocalDateTime());
    }

    public static Timestamp string2TimeStamp(String timeStampValue) {
        return Timestamp.valueOf(timeStampValue);
    }

    public static Long getMillis(int days, int hours, int minutes, int seconds) {
        return getMillis((days * 24) + hours, minutes, seconds);
    }

    public static Long getMillis(int hours, int minutes, int seconds) {
        return getMillis((hours * 60) + minutes, seconds);
    }

    public static Long getMillis(int minutes, int seconds) {
        return getMillis((minutes * 60) + seconds);
    }

    public static Long getMillis(int seconds) {
        return seconds * 1000L;
    }
}
