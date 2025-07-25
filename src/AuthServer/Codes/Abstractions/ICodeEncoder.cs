namespace AuthServer.Codes.Abstractions;

public interface ICodeEncoder<T> where T : class
{
    /// <summary>
    /// 
    /// </summary>
    string Encode(T code);
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="code"></param>
    /// <returns></returns>
    T? Decode(string? code);
}