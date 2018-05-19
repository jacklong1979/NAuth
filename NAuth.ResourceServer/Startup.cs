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
            #region 【方式1】IdentityServer + 密码、客户端模式
           
            services.AddAuthentication((options) =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                //ClockSkew:允许的服务器时间偏移量,默认是5分钟，如果不设置，时间有效期间到了以后，5分钟之内还可以访问资源
                options.TokenValidationParameters = new TokenValidationParameters()
                {                   
                    ValidateLifetime = true,//是否验证Token有效期
                    ClockSkew = TimeSpan.FromSeconds(2)//允许的服务器时间偏移量,默认是5分钟
                };
                options.RequireHttpsMetadata = false;//不需要https
                options.Audience = "API";//api范围 ,区分大小写
                options.Authority = "http://localhost:2000";//用来表示OIDC服务的地址

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
            app.UseAuthentication();// 添加认证中间件
            app.UseMvc();
        }
    }
}
