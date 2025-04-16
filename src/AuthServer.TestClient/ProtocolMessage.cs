using System.Net;
using System.Text;
using System.Text.Json;

namespace AuthServer.TestClient;

public class ProtocolMessage
{
    private const string _postTitle = "Working...";
    private const string _script = "<script language=\"javascript\">window.setTimeout(function() {document.forms[0].submit();}, 0);</script>";
    private const string _scriptButtonText = "Submit";
    private const string _scriptDisabledText = "Script is disabled. Click Submit to continue.";

    private readonly List<KeyValuePair<string, string>> _parameters = [];

    public string? IssuerAddress { get; set; }

    public ProtocolMessage(string json)
    {
        var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            ParseJsonObject(null, document.RootElement.EnumerateObject());
        }
        else
        {
            throw new InvalidOperationException("json is invalid");
        }
    }

    public ProtocolMessage(IEnumerable<KeyValuePair<string, string[]>> query)
    {
        foreach (var (parameter, collectionValue) in query)
        {
            foreach (var innerValue in collectionValue)
            {
                SetParameter(parameter, innerValue);
            }
        }
    }

    public ProtocolMessage(IEnumerable<KeyValuePair<string, string>> query)
    {
        foreach (var (parameter, value) in query)
        {
            SetParameter(parameter, value);
        }
    }

    public string BuildFormPost()
    {
        var strBuilder = new StringBuilder();
        strBuilder.Append("<html><head><title>");
        strBuilder.Append(WebUtility.HtmlEncode(_postTitle));
        strBuilder.Append("</title></head><body><form method=\"POST\" name=\"hiddenform\" action=\"");
        strBuilder.Append(WebUtility.HtmlEncode(IssuerAddress));
        strBuilder.Append("\">");
        foreach (var parameter in _parameters)
        {
            strBuilder.Append("<input type=\"hidden\" name=\"");
            strBuilder.Append(WebUtility.HtmlEncode(parameter.Key));
            strBuilder.Append("\" value=\"");
            strBuilder.Append(WebUtility.HtmlEncode(parameter.Value));
            strBuilder.Append("\" />");
        }

        strBuilder.Append("<noscript><p>");
        strBuilder.Append(WebUtility.HtmlEncode(_scriptDisabledText));
        strBuilder.Append("</p><input type=\"submit\" value=\"");
        strBuilder.Append(WebUtility.HtmlEncode(_scriptButtonText));
        strBuilder.Append("\" /></noscript>");
        strBuilder.Append("</form>");
        strBuilder.Append(_script);
        strBuilder.Append("</body></html>");
        return strBuilder.ToString();
    }

    public string BuildRedirectUrl()
    {
        var strBuilder = new StringBuilder(IssuerAddress);
        var issuerAddressHasQuery = IssuerAddress!.Contains('?');
        foreach (var parameter in _parameters)
        {
            if (!issuerAddressHasQuery)
            {
                strBuilder.Append('?');
                issuerAddressHasQuery = true;
            }
            else
            {
                strBuilder.Append('&');
            }

            strBuilder.Append(Uri.EscapeDataString(parameter.Key));
            strBuilder.Append('=');
            strBuilder.Append(Uri.EscapeDataString(parameter.Value));
        }

        return strBuilder.ToString();
    }

    public void RemoveParameter(string parameter)
    {
        var index = _parameters.FindIndex(x => x.Key == parameter);
        if (index != -1)
        {
            _parameters.RemoveAt(index);
        }
    }

    public void SetParameter(string parameter, string value) => _parameters.Add(new KeyValuePair<string, string>(parameter, value));
    public string? GetParameter(string parameter) => _parameters.Find(x => x.Key == parameter).Value;

    public void ReplaceParameter(string parameter, string value)
    {
        RemoveParameter(parameter);
        SetParameter(parameter, value);
    }

    private void ParseJsonValue(string propertyName, JsonElement jsonElement)
    {
        if (jsonElement.ValueKind == JsonValueKind.Object)
        {
            ParseJsonObject(propertyName, jsonElement.EnumerateObject());
        }
        else if (jsonElement.ValueKind == JsonValueKind.Array)
        {
            ParseJsonArray(propertyName, jsonElement.EnumerateArray());
        }
        else if (jsonElement.ValueKind is JsonValueKind.False or JsonValueKind.True)
        {
            SetParameter(propertyName, jsonElement.GetBoolean().ToString());
        }
        else if (jsonElement.ValueKind == JsonValueKind.String)
        {
            SetParameter(propertyName, jsonElement.GetString()!);
        }
        else if (jsonElement.ValueKind == JsonValueKind.Number)
        {
            SetParameter(propertyName, jsonElement.GetInt32().ToString());
        }
    }

    private void ParseJsonArray(string propertyName, JsonElement.ArrayEnumerator jsonArray)
    {
        foreach (var jsonElement in jsonArray)
        {
            ParseJsonValue(propertyName, jsonElement);
        }
    }

    private void ParseJsonObject(string? propertyName, JsonElement.ObjectEnumerator jsonObject)
    {
        foreach (var jsonProperty in jsonObject)
        {
            ParseJsonValue(jsonProperty.Name, jsonProperty.Value);
        }
    }
}
