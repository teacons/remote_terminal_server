package ru.fbear.remote_terminal_server

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.stereotype.Component
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.*
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.server.ResponseStatusException
import java.io.File
import java.nio.file.Paths
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED


@SpringBootApplication
class RemoteTerminalServerApplication

data class UserStatus(
    val token: String,
    var dir: File
)

@Component
class UserInfo {
    val usersStatus = mutableMapOf<String, UserStatus>()
    val tokenBlackList = mutableListOf<String>()
}


@RestController
@RequestMapping("/term")
class Terminal(
    val authenticationManager: AuthenticationManager,
    val jwtTokenUtil: JWTUtil,
    val userInfo: UserInfo
) {

    @GetMapping("/ls")
    @ResponseStatus(HttpStatus.OK)
    fun ls(@RequestHeader("Authorization") authHeader: String): List<String>? {
        val username = jwtTokenUtil.extractUsername(jwtTokenUtil.prepareAuthHeader(authHeader))
        val dir = getUserDir(username)

        return dir.listFiles()?.map {
            if (it.isDirectory)
                "/${it.name}"
            else
                it.name
        }
    }

    @GetMapping("/cd")
    @ResponseStatus(HttpStatus.OK)
    fun cd(
        @RequestHeader("Authorization") authHeader: String,
        @RequestParam(value = "dir", required = true)
        dirToChange: String
    ): Map<String, String?> {
        val username = jwtTokenUtil.extractUsername(jwtTokenUtil.prepareAuthHeader(authHeader))

        val currentDir = getUserDir(username)

        val newPath = if (dirToChange.contains("..")) {
            val level = dirToChange.count("..")
            val dirsInPath = currentDir.absolutePath.split(File.separator)
            dirsInPath.dropLast(level).joinToString(separator = File.separator)
        } else dirToChange

        val newDir = File(newPath)

        if (!newDir.isDirectory && !newDir.exists()) throw ResponseStatusException(HttpStatus.BAD_REQUEST)

        userInfo.usersStatus[username]!!.dir = newDir

        return mapOf("path" to newDir.absolutePath)
    }

    fun String.count(s: String): Int {
        return (this.length - this.replace(s, "").length) / s.length
    }

    @GetMapping("/who")
    @ResponseStatus(HttpStatus.OK)
    fun who(@RequestHeader("Authorization") authHeader: String): Map<String, String> {
        return userInfo.usersStatus.mapValues { it.value.dir.absolutePath }
    }

    @PostMapping("/kill")
    @ResponseStatus(HttpStatus.OK)
    fun kill(
        @RequestHeader("Authorization") authHeader: String,
        @RequestParam(value = "username", required = true)
        username: String
    ) {
        if (!userInfo.usersStatus.containsKey(username))
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Wrong username")
        userInfo.tokenBlackList.add(userInfo.usersStatus[username]!!.token)
        userInfo.usersStatus.remove(username)
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.OK)
    fun logout(@RequestHeader("Authorization") authHeader: String) {
        val token = jwtTokenUtil.prepareAuthHeader(authHeader)
        val username = jwtTokenUtil.extractUsername(token)
        userInfo.tokenBlackList.add(token)
        userInfo.usersStatus.remove(username)
    }


    fun getUserDir(username: String): File {
        return userInfo.usersStatus[username]!!.dir

    }

    @GetMapping("/auth")
    @ResponseStatus(HttpStatus.OK)
    fun auth(
        @RequestParam(value = "username", required = true)
        username: String,
        @RequestParam(value = "password", required = true)
        password: String
    ): AuthResponse? {
        if (userInfo.usersStatus.containsKey(username)) {
            try {
                jwtTokenUtil.validateToken(userInfo.usersStatus[username]!!.token)
                throw ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "User already exists"
                )
            } catch (_: ExpiredJwtException) {
            }

        }
        val authentication =
            try {
                authenticationManager.authenticate(UsernamePasswordAuthenticationToken(username, password))
            } catch (e: BadCredentialsException) {
                throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Имя или пароль неправильны", e)
            }
        val jwt = jwtTokenUtil.generateToken(authentication.principal as UserDetails)

        val dir = File(Paths.get("").toAbsolutePath().toString())

        userInfo.usersStatus[username] = UserStatus(jwt, dir)

        return AuthResponse(jwt, dir.absolutePath)
    }

}

data class AuthResponse(
    val token: String,
    val currentDir: String
)

data class MyUser(
    val login: String,
    val password: String,
    val role: String
)

@Repository
class UserRepository(
    passwordEncoder: PasswordEncoder
) {

    val users = listOf(
        MyUser("admin", passwordEncoder.encode("admin"), "ADMIN"),
        MyUser("jun", passwordEncoder.encode("jun"), "USER")
    )

    fun getByLogin(login: String) = users.firstOrNull { it.login == login }

}

@Service
class UserService(private val repository: UserRepository) : UserDetailsService {

    fun getByLogin(login: String) = repository.getByLogin(login)

    override fun loadUserByUsername(username: String?): UserDetails {
        if (username == null) throw UsernameNotFoundException("User not may be null")
        val user = getByLogin(username) ?: throw UsernameNotFoundException("User not found")
        return User.builder()
            .username(user.login)
            .password(user.password)
            .roles(user.role)
            .build()
    }
}

@Component
class PasswordEncoder : BCryptPasswordEncoder()

@Configuration
@EnableWebSecurity
class SecurityConfig(
    val userService: UserService,
    val jwtFilter: JWTFilter
) : WebSecurityConfigurerAdapter() {


    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(userService)
    }

    override fun configure(http: HttpSecurity) {
        http
            .httpBasic().disable()
            .csrf().disable()
            .authorizeRequests().antMatchers("/term/kill").hasRole("ADMIN")
            .and().authorizeRequests().antMatchers("/term/auth*").permitAll()
            .and().authorizeRequests().antMatchers("/term/**").hasAnyRole("USER", "ADMIN")
            .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and().addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
    }
}

@Service
class JWTUtil {
    @Value("\${jwt.secret}")
    private val secretKey: String? = null

    @Value("\${jwt.sessionTime}")
    private val sessionTime: Long = 0

    fun generateToken(userDetails: UserDetails): String {
        val claims = mutableMapOf<String, String>()
        val commaSeparatedListOfAuthorities =
            userDetails.authorities.joinToString(separator = ",") { it.authority }
        claims["authorities"] = commaSeparatedListOfAuthorities
        return createToken(claims, userDetails.username)
    }

    fun extractUsername(token: String): String {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).body.subject
    }

    fun extractAuthorities(token: String): String {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).body["authorities"].toString()
    }

    fun validateToken(token: String) {
        Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token)
    }


    private fun createToken(claims: Map<String, String>, subject: String): String {
        return Jwts.builder().setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(expireTimeFromNow())
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact()
    }

    private fun expireTimeFromNow(): Date {
        return Date(System.currentTimeMillis() + sessionTime)
    }

    fun prepareAuthHeader(authHeader: String) = authHeader.substring(7)
}

@Component
class JWTFilter(
    val jwtUtil: JWTUtil,
    val userInfo: UserInfo
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val authorizationHeader = request.getHeader("Authorization")
        var username: String? = null
        var jwt: String? = null
        try {
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                jwt = authorizationHeader.substring(7)
                username = jwtUtil.extractUsername(jwt)
            }

            if (userInfo.tokenBlackList.contains(jwt))
                throw IllegalAccessError()

            if (username != null && SecurityContextHolder.getContext().authentication == null) {
                val commaSeparatedListOfAuthorities = jwtUtil.extractAuthorities(jwt!!)
                val authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(commaSeparatedListOfAuthorities)
                val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(
                    username, null, authorities
                )
                SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken
            }
            chain.doFilter(request, response)

        } catch (e: ExpiredJwtException) {
            response.sendError(SC_UNAUTHORIZED, "Token expired")
        } catch (e: IllegalAccessError) {
            response.sendError(418)
        }
    }
}

fun main(args: Array<String>) {
    runApplication<RemoteTerminalServerApplication>(*args)
}
