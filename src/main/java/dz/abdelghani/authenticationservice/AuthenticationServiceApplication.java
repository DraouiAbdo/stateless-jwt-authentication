package dz.abdelghani.authenticationservice;

import dz.abdelghani.authenticationservice.sec.entities.AppRole;
import dz.abdelghani.authenticationservice.sec.entities.AppUser;
import dz.abdelghani.authenticationservice.sec.services.AccountServiceImpl;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class AuthenticationServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationServiceApplication.class, args);
    }
@Bean
PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
}
@Bean
    CommandLineRunner start(AccountServiceImpl accountService){
        return args -> {
            accountService.createNewRole(
                    new AppRole(null,"USER"));
            accountService.createNewRole(
                    new AppRole(null,"ADMIN"));
            accountService.createNewRole(
                    new AppRole(null,"CUSTOMER-MANAGER"));
            accountService.createNewRole(
                    new AppRole(null,"PRODUCT-MANAGER"));
            accountService.createNewRole(
                    new AppRole(null,"BILLING-MANAGER"));

            accountService.createNewUser(
                    new AppUser(null,"user1","123",new ArrayList<>()));
            accountService.createNewUser(
                    new AppUser(null,"admin","123",new ArrayList<>()));
            accountService.createNewUser(
                    new AppUser(null,"user2","123",new ArrayList<>()));
            accountService.createNewUser(
                    new AppUser(null,"user3","123",new ArrayList<>()));
            accountService.createNewUser(
                    new AppUser(null,"user4","123",new ArrayList<>()));

            accountService.addRoleToUser("user1","USER");
            accountService.addRoleToUser("admin","USER");
            accountService.addRoleToUser("admin","ADMIN");
            accountService.addRoleToUser("user2","USER");
            accountService.addRoleToUser("user2","CUSTOMER-MANAGER");
            accountService.addRoleToUser("user3","USER");
            accountService.addRoleToUser("user3","PRODUCT-MANAGER");
            accountService.addRoleToUser("user4","USER");
            accountService.addRoleToUser("user4","BILLING-MANAGER");

        };
    };

}
