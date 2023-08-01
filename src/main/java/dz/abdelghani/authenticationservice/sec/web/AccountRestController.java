package dz.abdelghani.authenticationservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import dz.abdelghani.authenticationservice.sec.JWTUtil;
import dz.abdelghani.authenticationservice.sec.entities.AppRole;
import dz.abdelghani.authenticationservice.sec.entities.AppUser;
import dz.abdelghani.authenticationservice.sec.services.AccountServiceImpl;
import lombok.Data;
import org.apache.catalina.filters.ExpiresFilter;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {
    AccountServiceImpl accountService;

    public AccountRestController(AccountServiceImpl accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> allUsers(){
        return accountService.allUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser createUser(@RequestBody AppUser appUser){
        return accountService.createNewUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole createRole(@RequestBody AppRole appRole){
        return accountService.createNewRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody  RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),
                                        roleUserForm.getRoleName());
    }

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response) throws Exception {


            String authorizationRequest = request.getHeader(JWTUtil.AUTH_HEADER);
            if(authorizationRequest !=null && authorizationRequest.startsWith(JWTUtil.PREFIX)){
                try {
                    String jwtRefreshToken = authorizationRequest.substring(JWTUtil.PREFIX.length());

                    Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                    JWTVerifier jwtVerifier=JWT.require(algorithm).build();

                    DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);

                    String username = decodedJWT.getSubject();
                    AppUser user = accountService.loadUserByUsername(username);

                    List<String> roles = user.getUserRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList());

                    String jwtAccessToken = JWT.create()
                            .withSubject(user.getUsername())
                            .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                            .withIssuer(request.getRequestURL().toString())
                            .withClaim("roles",roles)
                            .sign(algorithm);

                    Map<String,String> idToken = new HashMap<>();
                    idToken.put("access-token",jwtAccessToken);
                    idToken.put("refresh-token",jwtRefreshToken);

                    response.setContentType("application/json");

                    new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                } catch (Exception e){
                    throw e;
//                response.setHeader("error-message",e.getMessage());
//                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }




            } else {
                throw new RuntimeException("Refresh token required ");
            }



    }

    @GetMapping("/profile")
    public AppUser profile(Principal principal){

        return accountService.loadUserByUsername(principal.getName());
    }
}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}
