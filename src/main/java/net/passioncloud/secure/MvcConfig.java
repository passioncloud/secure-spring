package net.passioncloud.secure;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


@Configuration
@EnableWebSecurity
public class MvcConfig implements WebMvcConfigurer {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/home")
                .permitAll();
    }

    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/home")
                .setViewName("home");
        registry.addViewController("/")
                .setViewName("home");
        registry.addViewController("/hello")
                .setViewName("hello");
        registry.addViewController("/login")
                .setViewName("login");
    }
}