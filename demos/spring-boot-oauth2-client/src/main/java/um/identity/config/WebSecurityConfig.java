package um.identity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

	@Bean
	SecurityFilterChain clientSecurityFilterChain(HttpSecurity http, InMemoryClientRegistrationRepository clientRegistrationRepository)
			throws Exception {
		http.oauth2Login(withDefaults());
		http.logout(logout -> logout
				.logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository))
				.logoutSuccessUrl("/")
		);
		// @formatter:off
		http.authorizeHttpRequests(ex -> ex
				.requestMatchers(
						new AntPathRequestMatcher("/"),
						new AntPathRequestMatcher("/login/**"),
						new AntPathRequestMatcher("/oauth2/**"
						)).permitAll()
				.requestMatchers(new AntPathRequestMatcher("/nice.html")).hasAuthority("NICE")
				.anyRequest().authenticated());
		// @formatter:on
		return http.build();
	}

	@Component
	@RequiredArgsConstructor
	static class GrantedAuthoritiesMapperImpl implements GrantedAuthoritiesMapper {

		@Override
		public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
			authorities.forEach(authority -> {
				if (authority instanceof OidcUserAuthority oidcUserAuthority) {
					final var issuer = oidcUserAuthority.getIdToken().getClaimAsURL(JwtClaimNames.ISS);
					mappedAuthorities.addAll(extractAuthorities(oidcUserAuthority.getIdToken().getClaims()));

				} else if (authority instanceof OAuth2UserAuthority) {
					try {
						final var oauth2UserAuthority = (OAuth2UserAuthority) authority;
						final var userAttributes = oauth2UserAuthority.getAttributes();
						final var issuer = new URL(userAttributes.get(JwtClaimNames.ISS).toString());
						mappedAuthorities.addAll(extractAuthorities(userAttributes));

					} catch (MalformedURLException e) {
						throw new RuntimeException(e);
					}
				}
			});
			return mappedAuthorities;
		}

		@SuppressWarnings({"rawtypes", "unchecked"})
		private static Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
			return claims.values().stream().flatMap(claim -> {
						if (claim == null) {
							return Stream.empty();
						}
						if (claim instanceof String claimStr) {
							return Stream.of(claimStr.split(","));
						}
						if (claim instanceof String[] claimArr) {
							return Stream.of(claimArr);
						}
						if (Collection.class.isAssignableFrom(claim.getClass())) {
							final var iter = ((Collection) claim).iterator();
							if (!iter.hasNext()) {
								return Stream.empty();
							}
							final var firstItem = iter.next();
							if (firstItem instanceof String) {
								return (Stream<String>) ((Collection) claim).stream();
							}
							if (Collection.class.isAssignableFrom(firstItem.getClass())) {
								return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
							}
						}
						return Stream.empty();
					})
					/* Insert some transformation here if you want to add a prefix like "ROLE_" or force upper-case authorities */
					.map(SimpleGrantedAuthority::new)
					.map(GrantedAuthority.class::cast).toList();
		}

	}

}