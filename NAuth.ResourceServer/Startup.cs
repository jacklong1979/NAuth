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

namespace NAuth.ResourceServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            #region 【方式1】JwtRegisteredClaimNames 方式 直接读取配置文件信息，初始化Token 需要验证的信息,如果不同在一台服务，则产生的Token与验证的Token的服务器验证信息与产生的信息要一致
            var audienceConfig = Configuration.GetSection("TokenConfig");
            var symmetricKeyAsBase64 = audienceConfig["Secret"];
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
                ValidIssuer = audienceConfig["Issuer"],
                // 令牌的观众(颁发给谁)
                ValidateAudience = true,
                ValidAudience = audienceConfig["Audience"],
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

            #region 【方式1】IdentityServer + 密码、客户端模式

            //services.AddAuthentication((options) =>
            //{
            //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //})
            //.AddJwtBearer(options =>
            //{
            //    //ClockSkew:允许的服务器时间偏移量,默认是5分钟，如果不设置，时间有效期间到了以后，5分钟之内还可以访问资源
            //    options.TokenValidationParameters = new TokenValidationParameters()
            //    {                   
            //        ValidateLifetime = true,//是否验证Token有效期
            //        ClockSkew = TimeSpan.FromSeconds(2)//允许的服务器时间偏移量,默认是5分钟
            //    };
            //    options.RequireHttpsMetadata = false;//不需要https
            //    options.Audience = "API";//api范围 ,区分大小写
            //    options.Authority = "http://localhost:2000";//用来表示OIDC服务的地址

            //});
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
            app.UseAuthentication();// 添加认证中间件
            app.UseMvc();
        }
    }
}
