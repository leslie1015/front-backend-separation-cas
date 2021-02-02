这段时间一直在处理单点登录的问题，元旦前对接了基于SAML的单点登录认证，这几天又对接了一个基于CAS认证的，认证中心提供的对接文档都默认接入的client应用是前后端不分离的应用，所以踩了很多坑，过程中也找到一些前后端分离认证的共性问题。在此记录一下处理过程。

cas认证大致流程，简单画了个图
![输入图片说明](https://images.gitee.com/uploads/images/2021/0202/165439_e18e249c_2024853.png "未命名文件.png")

前后端不分离的应用集成很简单，springboot方式与springsecurity的集成官方文档都有很详细的说明
https://github.com/apereo/java-cas-client

前后端分离的认证，看了别人写的一些方案都不太适合我的场景，要么改动涉及认证中心，要么比较丑陋，比如使用iframe嵌套传递登录信息等方式，简单尝试了一下就放弃了。

我的处理思路：

1.先对接后台服务。把后台程序单独拿出来，看做是一个前后端不分离的应用，按照前后端不分离的方式对接，浏览器直接请求后台接口，是否对接成功也很容易验证，认证中心登录后浏览器页面跳转到后台接口返回的数据即可。

2.接入前端页面。即通过前端页面来调用后台接口。后台获取到前端发出的请求，校验未通过，返回302给调用方，但是跳转失败了。原因是ajax请求无法302跳转，这种情况不用考虑前端跳转了。

3.考虑后端处理。不分离的应用中后端跳转可以用response.sendRedirect()，思路是找到返回302请求的代码，看下能否拦截或者重写，返回401，并且带上要跳转的链接，前端获取链接后跳转。

4.检查是否有新问题引入。处理完跳转发现就可以正常对接了，可能有一些细节性问题处理，但是没有新的流程阻塞问题引入，如果有新问题，比如跨域，针对性解决即可。

以上是我在处理此类问题时总结出的大致方式，下面说说关键步骤，也就是跳转的处理方式

先说跳转处理方式，再分析

#### 一、未集成springsecurity
###### 代码包版本：
springboot：2.1.6.RELEASE
cas-server: 5.3.x
cas-client: cas-client-support-springboot:3.6.0

###### 1.定义一个跳转处理类，实现AuthenticationRedirectStrategy接口

```java
import lombok.SneakyThrows;
import org.jasig.cas.client.authentication.AuthenticationRedirectStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;

@Component
public class CustomAuthRedirectStrategy implements AuthenticationRedirectStrategy {

    @SneakyThrows
    @Override
    public void redirect(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String s) throws IOException {
        // 自定义一个后台接口，该controller接口内只写一个response.sendRedirect(应用首页)
        String dealUrl = "http://cas.app.com/api/1.0/users/loginRedirect";
        String encodeUrl = URLEncoder.encode(dealUrl, "utf-8");
        // cas认证中心登录页地址
        String loginUrl = "http://cas.proaim.com:8080/cas/login" + "?service=" + encodeUrl;
        httpServletResponse.setStatus(401);
        PrintWriter out = httpServletResponse.getWriter();
        // 格式自定义，前端能获取到loginUrl即可
        out.write("{\"errors\":[" + "\"" + loginUrl + "\"" + "]}");
    }
}
```

###### 2.修改cas filter初始化参数

```java
import com.proaimltd.web.casclient.filter.CustomAuthRedirectStrategy;
import org.jasig.cas.client.boot.configuration.CasClientConfigurer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CasAuthConfig implements CasClientConfigurer {
    @Override
    public void configureAuthenticationFilter(FilterRegistrationBean authenticationFilter) {
        // 源码中使用反射初始化authenticationRedirectStrategyClass, 用自定义的跳转类覆盖默认的authenticationRedirectStrategyClass
        authenticationFilter.getInitParameters().put("authenticationRedirectStrategyClass", CustomAuthRedirectStrategy.class.getName());
    }
}
```

注意点：此方式实现的跳转，如果ticket认证成功后，跳转回的地址带有;jsessionId=xxxxx，在配置中加上

```properties
server.servlet.session.tracking-modes=cookie
```

原因是应用不确定浏览器是否禁用了cookie，所以用这种方式来传递session到服务端，加上配置等于告诉应用session可以通过cookie来传递



##### 分析：

此方式直接引用了官方提供的springboot client包

```xml
<dependency>
    <groupId>org.jasig.cas.client</groupId>
    <artifactId>cas-client-support-springboot</artifactId>
    <version>3.6.0</version>
</dependency>
```

代码跟踪到org.jasig.cas.client.authentication.AuthenticationFilter的doFilter方法，可以看到跳转的代码 this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo)，是一个接口

```java
// 省略非关键代码
public final void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest)servletRequest;
    HttpServletResponse response = (HttpServletResponse)servletResponse;
    if (this.isRequestUrlExcluded(request)) {...} else {
        if (assertion != null) {...} else {
            ...
            if (!CommonUtils.isNotBlank(ticket) && !wasGatewayed) {
                ....
                String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, this.getProtocol().getServiceParameterName(), modifiedServiceUrl, this.renew, this.gateway, this.method);
                this.logger.debug("redirecting to \"{}\"", urlToRedirectTo);
                // 此处跳转
                this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo);
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
```

构造函数中，authenticationRedirectStrategy接口的默认实现是 DefaultAuthenticationRedirectStrategy

```java
protected AuthenticationFilter(Protocol protocol) {
    super(protocol);
    this.renew = false;
    this.gateway = false;
    this.gatewayStorage = new DefaultGatewayResolverImpl();
    this.authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();
    this.ignoreUrlPatternMatcherStrategyClass = null;
}
```

DefaultAuthenticationRedirectStrategy方法内仅有跳转相关的代码，所以可以放心替代

```java
public final class DefaultAuthenticationRedirectStrategy implements AuthenticationRedirectStrategy {
    public DefaultAuthenticationRedirectStrategy() {
    }

    public void redirect(HttpServletRequest request, HttpServletResponse response, String potentialRedirectUrl) throws IOException {
        response.sendRedirect(potentialRedirectUrl);
    }
}
```

继续看该filter的代码，找到initInternal方法，该方法在client程序启动时初始化了AuthenticationRedirectStrategy的实现，可以看到此处通过getClass方法获取AuthenticationRedirectStrategy的实现类，

```java
protected void initInternal(FilterConfig filterConfig) throws ServletException {
		// 省略前面 
    	.....
        Class<? extends AuthenticationRedirectStrategy> authenticationRedirectStrategyClass = this.getClass(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS);
        if (authenticationRedirectStrategyClass != null) {
            this.authenticationRedirectStrategy = (AuthenticationRedirectStrategy)ReflectUtils.newInstance(authenticationRedirectStrategyClass, new Object[0]);
        }
    }

}
```

getClass方法获取ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS中配置的类名，通过反射获取实现类信息

```java
public <T> Class<? extends T> getClass(final ConfigurationKey<Class<? extends T>> configurationKey) {
    return (Class)this.getValue(configurationKey, new BaseConfigurationStrategy.Parser<Class<? extends T>>() {
        public Class<? extends T> parse(String value) {
            try {
                return ReflectUtils.loadClass(value);
            } catch (IllegalArgumentException var3) {
                return (Class)configurationKey.getDefaultValue();
            }
        }
    });
}
```

官方提供了cas filter参数初始化的方式，大致意思是：
官方并没有在配置文件中提供所有的配置选项，只提供了最常用的，但是未提供的属性也可以实现配置，可以在@EnableCasClient注解下实现CasClientConfigurer类，并为相关的Filter覆盖适当的配置方法。
![输入图片说明](https://images.gitee.com/uploads/images/2021/0202/171142_41916142_2024853.png "cas_config.png")

按照示例，即可覆盖原有的

如下

```java
authenticationFilter.getInitParameters().put("authenticationRedirectStrategyClass", CustomAuthRedirectStrategy.class.getName());
```

可以将AuthenticationFilter#doFilter中的this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo)指向我们自定义的跳转方法，返回401

#### 二、集成了springsecurity

###### 代码包版本：
springboot：2.1.6.RELEASE
cas-server: 5.3.x
cas-client: spring-security-cas:5.1.5.RELEASE

前后端不分离应用集成springsecurity的方式很简单，代码可以参考 https://github.com/leslie1015/security_cas

同样，先来说说如何修改跳转，返回401

##### 1.定义一个CustomAuthenticationEntryPoint，实现 AuthenticationEntryPoint, InitializingBean 

```java
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    // 如果系统已有JWT等认证，此处可以定义一个开关，控制不影响原先认证逻辑
    private final Boolean isCasLogin;
    // 配置信息
    private final CasProvider casProvider;

    public CustomAuthenticationEntryPoint(Boolean isCasLogin, CasProvider casProvider) {
        this.isCasLogin = isCasLogin;
        this.casProvider = casProvider;
    }

    @Override
    public final void commence(HttpServletRequest servletRequest, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        if (!isCasLogin) {
            // 原先JWT或者其他认证方式的代码，如果没有则忽略
            ...
            return;
        }
        // 构造未登录情况需要跳转的login页面url
        // 登录地址（指定的一个后台controller接口）
        String encodeUrl = URLEncoder.encode(casProvider.getAppServerUrl() + casProvider.getAppLoginUrl(), "utf-8");
        // CAS认证中心页面地址，参数service带上登录地址，登录成功后会带上ticket跳转回service指定的地址
        String redirectUrl = casProvider.getCasServerLoginUrl() + "?service=" + encodeUrl;
        // 返回401
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter out = response.getWriter();
        // 返回与前端约定的格式，前端能获取到redirectUrl跳转即可
        out.write("{\"errors\":[" + "\"" + redirectUrl + "\"" + "]}");
    }
}
```

##### 2.SecurityConfig.java#configure中配置authenticationEntryPoint，指向自定义的CustomAuthenticationEntryPoint

```java
@Override
public void configure(HttpSecurity http) throws Exception {
    http
            .cors()
            .and()
            .csrf().disable()
            .exceptionHandling()
        	// 配置自定义的CustomAuthenticationEntryPoint（主要看这里，其他按需配置）
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint(AuthUtils.isCasLogin, casProvider))
            .and()
            .authorizeRequests()
            .regexMatchers(PermitUrlsConfig.permitUrlArray()).permitAll()
            .antMatchers(HttpMethod.OPTIONS).permitAll()
            .antMatchers(appConfigBean.getAuthenticatedUrls()).permitAll()
        	.anyRequest().authenticated();
	
    configureJwtFilter(http);
    if (AuthUtils.isCasLogin) {
        casProvider.configureCasFilter(http, authenticationManager());
    }
}
```



##### 分析

此处引用的代码包是spring-security-cas，方便我们将cas的各种filter直接配置到security框架中

```xml
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-cas</artifactId>
   <version>5.1.5.RELEASE</version>
</dependency>
```

我们先了解一下springsecurity框架的入口点entry-point，这个入口点其实是被ExceptionTranslationFilter引用的，ExceptionTranslationFilter过滤器的作用的异常翻译，出现认证、访问异常的时候，通过入口点决定redirect、forward的操作。异常情况下调用handleSpringSecurityException

```java
public class ExceptionTranslationFilter extends GenericFilterBean {
    
    // 前面省略
    	...
       public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		try {
			chain.doFilter(request, response);

			logger.debug("Chain processed normally");
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			....
            RuntimeException ase = (AuthenticationException) throwableAnalyzer
					.getFirstThrowableOfType(AuthenticationException.class, causeChain);
            
			if (ase == null) {
				ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
						AccessDeniedException.class, causeChain);
			}
			if (ase != null) {
				if (response.isCommitted()) {
					throw new ServletException("des.", ex);
				}
                // 异常情况下处理
				handleSpringSecurityException(request, response, chain, ase);
			}
			else {
				...
			}
		}
	} 
    
}

```

该方法最终调用了sendStartAuthentication方法处理

```java
private void handleSpringSecurityException(HttpServletRequest request,
      HttpServletResponse response, FilterChain chain, RuntimeException exception)
      throws IOException, ServletException {
   if (exception instanceof AuthenticationException) {
      logger.debug(
            "Authentication exception occurred; redirecting to authentication entry point",
            exception);

      sendStartAuthentication(参数1...);

   }
   else if (exception instanceof AccessDeniedException) {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (authenticationTrustResolver.isAnonymous(authentication) || authenticationTrustResolver.isRememberMe(authentication)) {
         logger.debug("des", exception);

         sendStartAuthentication(参数2...);
      }
      else {
         ....
      }

   }
}
```

sendStartAuthentication方法调用了authenticationEntryPoint.commence(request, response, reason);

```java
protected void sendStartAuthentication(HttpServletRequest request,
      HttpServletResponse response, FilterChain chain,
      AuthenticationException reason) throws ServletException, IOException {
   // SEC-112: Clear the SecurityContextHolder's Authentication, as the
   // existing Authentication is no longer considered valid
   SecurityContextHolder.getContext().setAuthentication(null);
   requestCache.saveRequest(request, response);
   logger.debug("Calling Authentication entry point.");
   authenticationEntryPoint.commence(request, response, reason);
}
```

关键的代码就是authenticationEntryPoint.commence(request, response, reason)，其实这时候已经很明显了，authenticationEntryPoint是一个接口，有多个官方实现类，包括引入的spring-security-cas中实现的CasAuthenticationEntryPoint，commence方法最终也是response.sendRedirect(redirectUrl)方式跳转

```java
public class CasAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    	...
        public final void commence(HttpServletRequest servletRequest, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        String urlEncodedService = this.createServiceUrl(servletRequest, response);
        String redirectUrl = this.createRedirectUrl(urlEncodedService);
        this.preCommence(servletRequest, response);
        response.sendRedirect(redirectUrl);
	}
}


```

SecurityConfig中指定我们自定义的authenticationEntryPoint即可，但是为什么在这里指定就可以呢？
ExceptionTranslationFilter中authenticationEntryPoint的定义来自构造函数，我们在SecurityConfig#configure(HttpSecurity http)方法中有如下配置：

```java
@Override
public void configure(HttpSecurity http) throws Exception {
    http
            ...
            .exceptionHandling()
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint(AuthUtils.isCasLogin, casProvider))
			...
}
```

exceptionHandling(）方法初始化了ExceptionHandlingConfigurer类，

```java
public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
   return getOrApply(new ExceptionHandlingConfigurer<>());
}
```

SecurityConfig#configure(HttpSecurity http)中接着又调用了ExceptionHandlingConfigurer的authenticationEntryPoint方法，该方法指定了authenticationEntryPoint的具体实现类

```java
public ExceptionHandlingConfigurer<H> authenticationEntryPoint(
      AuthenticationEntryPoint authenticationEntryPoint) {
   this.authenticationEntryPoint = authenticationEntryPoint;
   return this;
}
```

SecurityConfig上的注解@EnableWebSecurity初始化了WebSecurityConfiguration.class，该配置中定义了springSecurityFilterChain，通过层层调用，最终调用了ExceptionHandlingConfigurer#configure(H http)方法，该方法中获取了我们在SecurityConfig中指定的authenticationEntryPoint，然后调用ExceptionTranslationFilter的构造函数初始化，最终系统认证失败的时候，ExceptionTranslationFilter的doFilter就会调用我们自己定义的authenticationEntryPoint



#### 三、另外一种修改跳转的思路

通过源码可以发现，实现跳转的代码最终都是通过response.sendRedirect(redirectUrl)实现，该方法在前后端分离的应用下是无法实现页面跳转的，那能否重写HttpServletResponse的sendRedirect方法呢？

可以定义CasResponseWrapper，继承HttpServletResponseWrapper，在原先传入HttpServletResponse的地方传入

new CasResponseWrapper(httpServletResponse, httpServletRequest, casProperties)

系统中再有调用response.sendRedirect方法的地方就会调用到我们自定义的跳转方法。无法重写跳转方法的时候可以尝试。

该方式在之前对接客户方提供的封装好的saml client认证包的时候使用过，亲测有效。

```java
public class CasResponseWrapper extends HttpServletResponseWrapper {

    private final HttpServletResponse httpServletResponse;

    private final HttpServletRequest httpServletRequest;

    private final CasProperties casProperties;

    public CasResponseWrapper(HttpServletResponse response, HttpServletRequest request, CasProperties casProperties) {
        super(response);
        this.httpServletResponse = response;
        this.httpServletRequest = request;
        this.casProperties = casProperties;
    }

    /**
     *
     *
     * @param redirectPath
     */
    @SneakyThrows
    @Override
    public void sendRedirect(String redirectPath) {
        if (前后端不分离) {
            httpServletResponse.sendRedirect(redirectPath);
            return;
        }
        
        httpServletRequest.setAttribute("redirectPath", redirectPath);
		// 跳转到指定的controller，并且在请求头中带上要跳转的地址，在该controller返回401，或者抛出特定异常，定义异常拦截器返回401
        httpServletRequest.getRequestDispatcher("/loginRedirect")
                .forward(httpServletRequest, httpServletResponse);
    }
}
```

#### 可能遇到的问题：

##### 1.跨域。
我的处理方式是在接入前端应用时启了个nginx代理，前端打包放入指定目录，前后端的访问都由nginx代理

###### 2.浏览器循环跳转或者跳到空白页。
这种情况可能有很多种原因，需要跟踪代码到源码包里面具体查看，因为认证失败可能有多重情况，但是返回到应用端异常查看的时候都一样，比如我在调试的时候遇到service与ticket不匹配，ticket校验不通过的情况，需要检查登录页面url的service参数，与调用认证中心校验时的service是否一致，因为在代码调试过程中，可能有配置错误或者手动修改过配置，校验ticket的时候需要传入service参数与ticket参数，如果不一致，则不能通过，这种情况下可能就会直接认证失败跳到空白页。
集成springsecurity时，登录后如果未授权，检查授权信息为空，可能就会循环跳转，因为无授权信息，框架会认为校验失败，跳到首页，但是实际上已经登陆过将session写入cookie了，发起请求又认为是认证过的，然后又无权限导致跳转...

好像还有别的情况会循环重定向...总之debug进去找到原因，然后解决
