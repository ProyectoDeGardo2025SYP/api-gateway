package co.edu.uco.burstcar.apigateway.aplicacion.casodeuso.token;

import co.edu.uco.burstcar.apigateway.dominio.modelo.UsuarioRol;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
public class ValidarTokenServicio {

    public UsuarioRol extraerRol(Jwt jwt) {
        String nombre = jwt.getSubject();
        String rol = jwt.getClaimAsString("rol");
        return new UsuarioRol(nombre, rol);
    }
}
