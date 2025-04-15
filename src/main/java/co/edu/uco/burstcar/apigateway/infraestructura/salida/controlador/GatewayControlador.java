package co.edu.uco.burstcar.apigateway.infraestructura.salida.controlador;

import co.edu.uco.burstcar.apigateway.aplicacion.casodeuso.token.ValidarTokenServicio;
import co.edu.uco.burstcar.apigateway.dominio.modelo.UsuarioRol;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

@RestController
@RequestMapping("/publico")
public class GatewayControlador {
    private final ValidarTokenServicio validarTokenService;

    public GatewayControlador(ValidarTokenServicio validarTokenService) {
        this.validarTokenService = validarTokenService;
    }


    @GetMapping("/inicio")
    public UsuarioRol info(@AuthenticationPrincipal Jwt jwt) {
        return validarTokenService.extraerRol(jwt);
    }
}
