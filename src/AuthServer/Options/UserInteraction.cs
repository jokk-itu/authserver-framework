namespace AuthServer.Options;

public class UserInteraction
{
    public string? LoginUri { get; set; }
    public string? ConsentUri { get; set; }
    public string? AccountSelectionUri { get; set; }
    public string? EndSessionUri { get; set; }
    public string? VerificationUri { get; set; }
}