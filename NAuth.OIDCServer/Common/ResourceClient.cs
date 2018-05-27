using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;


namespace NAuth.OIDCServer.Common
{  
    /// <summary>
    /// 设置Resource和Client
    /// </summary>
    public  class ResourceClient
    {
        //static string secretString = "lkc311@163.com";
        static TokenConfig _TokenConfig;
        public static void GetTokenConfig(IConfigurationSection section)
        {            
            var symmetricKeyAsBase64 = section["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var tokenConfig = new TokenConfig
            {
                #region 初始化 TokenConfig 
                Secret = section["Secret"], //密钥
                Issuer = section["Issuer"], //发行者
                Audience = section["Audience"], //令牌的观众
                TokenType = section["TokenType"], //表示令牌类型，该值大小写不敏感，必选项，可以是bearer类型或mac类型。
                Scope = section["Scope"], //表示权限范围，如果与客户端申请的范围一致，此项可省略
                Subject = section["Subject"], //主题
                ExpiresIn = Convert.ToInt32(section["ExpiresIn"]), //表示过期时间，单位为秒。如果省略该参数，必须其他方式设置过期时间。
                ClientId = section["ClientId"], //表示客户端的ID，必选项
                ResponseType = section["ResponseType"], //表示授权类型，必选项，此处的值固定为"code"
                RedirectUri = section["RedirectUri"],
                State = section["State"], //表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值。
                SigningCredentials = signingCredentials
                #endregion
            };
            _TokenConfig = tokenConfig;
        }
       
        /// <summary>
        /// 定义授权范围（通过API可以访问的资源）
        /// </summary>
        /// <returns></returns>
        public static  IEnumerable<ApiResource> GetApiResource()
        {
            return new List<ApiResource>
            {
                //给api资源定义Scopes 必须与 Client 的 AllowedScopes 对应上，不然显示 invalid_scope
                new ApiResource(_TokenConfig.Scope,"my api"),
                new ApiResource("wiz","my wiz")
            };
        }
        /// <summary>
        /// OIDC : OpenID Connect implicit flow client (MVC)
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile()
            };
        }
        /// <summary>
        /// 客户端注册，客户端能够访问的资源（通过：AllowedScopes）
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<Client> GetClients()
        {
            //注意：客户端不能包含重复ID
            // var keyByteArray = Encoding.ASCII.GetBytes(_TokenConfig.Secret);
            // var signingKey = new SymmetricSecurityKey(keyByteArray);
            return new List<Client>
            {
                /*
                客户端模式（Client Credentials）：和用户无关，用于应用程序与 API 资源的直接交互场景。
                密码模式（resource owner password credentials）：和用户有关，一般用于第三方登录。
                简化模式-With OpenID（implicit grant type）：仅限 OpenID 认证服务，用于第三方用户登录及获取用户信息，不包含授权。
                简化模式-With OpenID & OAuth（JS 客户端调用）：包含 OpenID 认证服务和 OAuth 授权，但只针对 JS 调用（URL 参数获取），一般用于前端或无线端。
                混合模式-With OpenID & OAuth（Hybrid Flow）：推荐使用，包含 OpenID 认证服务和 OAuth 授权，但针对的是后端服务调用。
                */
                #region 授权中心配置,可以增加多个不同的 Client
              new Client
                {
                    ClientId="Client",//注意：客户端不能包含重复ID
                    AllowedGrantTypes=GrantTypes.ClientCredentials, // 没有交互性用户，使用 clientid/secret 实现认证。client credentials模式则不需要对账号密码验证
                    ClientSecrets={new Secret(_TokenConfig.Secret.Sha256())},
                    AccessTokenLifetime=_TokenConfig.ExpiresIn,
                    AllowedScopes={ _TokenConfig.Scope }//  // 客户端有权访问的范围（Scopes）
                },
               new Client
                {

                    ClientId ="Client2",//注意：客户端不能包含重复ID
	                // 没有交互性用户，使用 clientid/secret 实现认证。
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
	                // 用于认证的密码
                     ClientSecrets = {new Secret(_TokenConfig.Secret.Sha256())},
                     AccessTokenLifetime=_TokenConfig.ExpiresIn,
                     AccessTokenType =AccessTokenType.Jwt,
	                // 客户端有权访问的范围（Scopes）
                    AllowedScopes = { _TokenConfig.Scope }
                },
                new Client
                {
                    ClientId ="Client3",//注意：客户端不能包含重复ID
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                    AccessTokenType = AccessTokenType.Jwt,
                    AccessTokenLifetime = _TokenConfig.ExpiresIn,
                    IdentityTokenLifetime = _TokenConfig.ExpiresIn,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    SlidingRefreshTokenLifetime = _TokenConfig.ExpiresIn,
                    AllowOfflineAccess = true,
                    RefreshTokenExpiration = TokenExpiration.Absolute,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    AlwaysSendClientClaims = true,
                    Enabled = true,
                    ClientSecrets =
                    {
                        new Secret(_TokenConfig.Secret.Sha256())
                    },
                    AllowedScopes = { IdentityServerConstants.StandardScopes.OfflineAccess, _TokenConfig.Scope }
                    //ClientId = "pwdClient",
                    //AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,//Resource Owner Password模式需要对账号密码进行验证（如果是client credentials模式则不需要对账号密码验证了）：
                    //ClientSecrets ={new Secret(secretString.Sha256())},                  
                    //AllowedScopes =
                    //{
                    //    "UserApi"
                    //    //如果想带有RefreshToken，那么必须设置：StandardScopes.OfflineAccess
                    //    //如果是Client Credentials模式不支持RefreshToken的，就不需要设置OfflineAccess
                    //    //StandardScopes.OfflineAccess
                    //}
                    // //AccessTokenLifetime = 3600, //AccessToken的过期时间， in seconds (defaults to 3600 seconds / 1 hour)
                    ////AbsoluteRefreshTokenLifetime = 60, //RefreshToken的最大过期时间，in seconds. Defaults to 2592000 seconds / 30 day
                    ////RefreshTokenUsage = TokenUsage.OneTimeOnly,   //默认状态，RefreshToken只能使用一次，使用一次之后旧的就不能使用了，只能使用新的RefreshToken
                    ////RefreshTokenUsage = TokenUsage.ReUse,   //可重复使用RefreshToken，RefreshToken，当然过期了就不能使用了
                },
                   // OpenID Connect implicit flow client (MVC)
                new Client
                {
                    ClientId = "Client4",//注意：客户端不能包含重复ID
                    ClientName = "MVC Client",
                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
                     ClientSecrets =
                    {
                        new Secret(_TokenConfig.Secret.Sha256())
                    },
                    RedirectUris = { "http://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5002" },

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "UserApi"
                    },
                    AllowOfflineAccess = true,//AllowOfflineAccess. 我们还需要获取Refresh Token, 这就要求我们的网站必须可以"离线"工作, 这里离线是指用户和网站之间断开了, 并不是指网站离线了.这就是说网站可以使用token来和api进行交互, 而不需要用户登陆到网站上
                    AlwaysIncludeUserClaimsInIdToken=true //包含用户和token信息
                },
                   // JavaScript Client
                new Client
                {
                    ClientId ="Client5",//注意：客户端不能包含重复ID
                    ClientName = "JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,
                    RedirectUris = { "http://localhost:5003/callback.html" },
                    PostLogoutRedirectUris = { "http://localhost:5003/index.html" },
                    AllowedCorsOrigins = { "http://localhost:5003" },

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "UserApi"
                    },
                }
                #endregion
            };
        }       
    }
}
