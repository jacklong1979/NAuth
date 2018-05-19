using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace NAuth.ClientServer
{
    public class Program
    {
        public static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();


        private static async Task MainAsync()
        {
            //获取TOKEN地址
            var dico = await DiscoveryClient.GetAsync("http://localhost:2000");

            #region 客户端模式
           // var tokenClient = new TokenClient(dico.TokenEndpoint, "Client", "lkc311@163.com");
            //var tokenresp = await tokenClient.RequestClientCredentialsAsync("API");
            #endregion
            #region 密码模式
            var tokenClient = new TokenClient(dico.TokenEndpoint, "Client3", "lkc311@163.com");
            var tokenresp = await tokenClient.RequestResourceOwnerPasswordAsync("admin","123","API");
            #endregion
            if (tokenresp.IsError)
            {
                Console.WriteLine(tokenresp.Error);
                return;

            }
            Console.WriteLine(tokenresp.Json);
            Console.WriteLine("\n\n");


            var client = new HttpClient();
            client.SetBearerToken(tokenresp.AccessToken);

            var resp = await client.GetAsync("http://localhost:2001/api/values");
            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine(resp.StatusCode);
            }
            else
            {
                var content = await resp.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
            }
            Console.ReadKey();

        }
    }
}
