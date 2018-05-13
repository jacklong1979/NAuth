using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NAuth.OIDCServer.Common;
namespace NAuth.OIDCServer
{
    public class Startup
    {
        public Startup(IHostingEnvironment env,IConfiguration configuration)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //读取配置信息
            var tokenSection = this.Configuration.GetSection("TokenConfig");
            var obj= services.Configure<TokenConfig>(tokenSection);

            /*
               使用时重写构造函数，包含注入的配置信息
                public HomeController(IOptions<TokenConfig> setting) {
                    TokenConfig = setting.Value;
                }
             */
            #region
            ResourceClient.GetTokenConfig(tokenSection);//初始化配置文件
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiResources(tokenSection)
                .AddResourceAndClient(services)
                .AddInMemoryApiResources(ResourceClient.GetApiResource())//添加api资源
                .AddInMemoryClients(ResourceClient.GetClients())           //添加客户端   
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>();

            // .AddTestUsers(APIClient.GeTestUsers());//优化于上面的 ResourceOwnerPasswordValidator

            ////RSA：证书长度2048以上，否则抛异常
            ////配置AccessToken的加密证书
            //var rsa = new RSACryptoServiceProvider();
            ////从配置文件获取加密证书
            //rsa.ImportCspBlob(Convert.FromBase64String(Configuration["SigningCredential"]));
            ////IdentityServer4授权服务配置
            //services.AddIdentityServer()
            //    .AddSigningCredential(new RsaSecurityKey(rsa))    //设置加密证书
            //    //.AddTemporarySigningCredential()    //测试的时候可使用临时的证书
            //    .AddInMemoryScopes(TokenClient.GetScopes())
            //    .AddInMemoryClients(TokenClient.GetClients())
            //    //如果是client credentials模式那么就不需要设置验证User了
            //    .AddResourceOwnerValidator<MyUserValidator>() //User验证接口
            //    //.AddInMemoryUsers(OAuth2Config.GetUsers())    //将固定的Users加入到内存中
            //    ;

            #endregion
            services.AddMvc();
           
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseIdentityServer();
            app.UseMvc();
        }
    }
}
