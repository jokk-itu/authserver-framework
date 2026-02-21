namespace AuthServer.Options;

public class TokenValidationOptions
{
    public TimeSpan ClockSkew { get; set; }

    public TimeSpan ClientTokenLifetimeWindow { get; set; }
}