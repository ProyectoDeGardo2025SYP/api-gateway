package co.edu.uco.burstcar.apigateway.infraestructura.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.core.convert.converter.Converter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;


@Configuration
public class SeguridadConfiguracion{

    @Value("${token.llave-publica}")
    private String rutaLlavePublica;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .cors(corsSpec -> corsSpec.configurationSource(corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/publico/**").permitAll()
                        .pathMatchers("/prestador/sesion").permitAll()
                        .pathMatchers("/solicitante/sesion").permitAll()
                        .pathMatchers("/prestador/*/calificacion").hasRole("solicitante")
                        .pathMatchers("/prestador/ubicacion/nuevo").hasRole("prestador")
                        .pathMatchers("/prestador/nuevo").hasRole("prestador")
                        .pathMatchers("/solicitante/nuevo").hasRole("solicitante")
                        .pathMatchers("/servicio/ubicacion/nuevo").hasRole("solicitante")
                        .pathMatchers("/servicio/destino/nuevo").hasRole("solicitante")
                        .pathMatchers("/servicio/nuevo").hasRole("solicitante")
                        .pathMatchers("/servicio/todos").permitAll()
                        .pathMatchers("paquete/servicio/*/informacion").permitAll()
                        .pathMatchers("/servicio/oferta/nueva").hasRole("prestador")
                        .pathMatchers("/servicio/oferta/todos").permitAll()
                        .pathMatchers("/servicio/*/cambio").hasRole("solicitante")
                        .pathMatchers("/servicio/*/estado").permitAll()
                        .pathMatchers("/servicio/*/cambio/informacion").hasRole("solicitante")
                        .pathMatchers("/servicio/oferta/*/cambio/estado").hasRole("solicitante")
                        .pathMatchers("/paquete/contenido/nuevo").hasRole("solicitante")
                        .pathMatchers("/paquete/peso/nuevo").hasRole("solicitante")
                        .pathMatchers("/paquete/nuevo").hasRole("solicitante")
                        .pathMatchers("/paquete/poliza/nueva").hasRole("solicitante")
                        .pathMatchers("/paquete/*/informacion").permitAll()
                        .pathMatchers("/paquete/contenido/*/cambio").hasRole("solicitante")
                        .pathMatchers("/paquete/peso/*/cambio").hasRole("solicitante")
                        .pathMatchers("/paquete/*/cambio").hasRole("solicitante")
                        .pathMatchers("paquete/peso/*/informacion").permitAll()
                        //.pathMatchers("/prestador/**").hasRole("prestador")
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwtSpec -> jwtSpec.jwtAuthenticationConverter(grantedAuthoritiesConverter()))
                )
                .build();
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("rol");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() throws Exception{
        Resource resource = new ClassPathResource(rutaLlavePublica);
        CertificateFactory certificado = CertificateFactory.getInstance("X.509");
        X509Certificate generacionDeCertificado = (X509Certificate) certificado.generateCertificate(resource.getInputStream());
        PublicKey publicKey = generacionDeCertificado.getPublicKey();
        return NimbusReactiveJwtDecoder.withPublicKey((RSAPublicKey) publicKey).build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:8100"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true); //

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
