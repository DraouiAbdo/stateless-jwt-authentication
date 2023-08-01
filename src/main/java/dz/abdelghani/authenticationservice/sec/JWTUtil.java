package dz.abdelghani.authenticationservice.sec;

public class JWTUtil {
    public static final String SECRET = "draoui";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 1*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 1*60*1000;

}
