using System.Net.Http;
using System.Threading.Tasks;

namespace ADMIN.Getways.Interface
{
    public interface IResponseGetaway
    {
        Task<HttpResponseMessage> GetTAsync(string url);
        //Task<HttpResponseMessage> SendTAsync<T>(T t, string url, HttpMethod method);
        Task<string> SendTAsync<T>(T t, string url, HttpMethod method);
    }
}
