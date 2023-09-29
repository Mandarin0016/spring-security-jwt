package bg.stride.security.jwt.excpetion;

public class InvalidBearerTokenException extends TokenException {

    public InvalidBearerTokenException(String message) {
        super(message);
    }

    public InvalidBearerTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
