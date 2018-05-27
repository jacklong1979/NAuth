using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
            #region 跨域
            services.AddCors(options =>
            {
                // this defines a CORS policy called "default"
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins("http://localhost:2000")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
            #endregion
            #region 读取配置信息
            var tokenSection = this.Configuration.GetSection("TokenConfig");
            var obj= services.Configure<TokenConfig>(tokenSection);

            /*
               使用时重写构造函数，包含注入的配置信息
                public HomeController(IOptions<TokenConfig> setting) {
                    TokenConfig = setting.Value;
                }
             */
            #endregion  
            #region 客户端，密码模式
            ResourceClient.GetTokenConfig(tokenSection);//初始化配置文件
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryApiResources(tokenSection)
                .AddResourceAndClient(services)
                .AddInMemoryApiResources(ResourceClient.GetApiResource())//添加api资源
                .AddInMemoryClients(ResourceClient.GetClients())           //添加客户端   
                .AddInMemoryIdentityResources(ResourceClient.GetIdentityResources())
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
            #region 【方式1】JwtRegisteredClaimNames 方式 直接读取配置文件信息，初始化Token 需要验证的信息,如果不同在一台服务，则产生的Token与验证的Token的服务器验证信息与产生的信息要一致
            
            var symmetricKeyAsBase64 = tokenSection["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);
            var tokenValidationParameters = new TokenValidationParameters
            {
                #region 下面三个参数是必须
                // 签名秘钥
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                // 发行者(颁发机构)
                ValidateIssuer = true,
                ValidIssuer = tokenSection["Issuer"],
                // 令牌的观众(颁发给谁)
                ValidateAudience = true,
                ValidAudience = tokenSection["Audience"],
                #endregion
                // 是否验证Token有效期
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
                /***********************************TokenValidationParameters的参数默认值***********************************/
                // RequireSignedTokens = true,
                // SaveSigninToken = false,
                // ValidateActor = false,
                // 将下面两个参数设置为false，可以不验证Issuer和Audience，但是不建议这样做。
                // ValidateAudience = true,
                // ValidateIssuer = true, 
                // ValidateIssuerSigningKey = false,
                // 是否要求Token的Claims中必须包含Expires
                // RequireExpirationTime = true,
                // 允许的服务器时间偏移量
                // ClockSkew = TimeSpan.FromSeconds(300),//TimeSpan.Zero
                // 是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
                // ValidateLifetime = true
            };
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                //不使用https
                //o.RequireHttpsMetadata = false;
                o.TokenValidationParameters = tokenValidationParameters;
            });
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
