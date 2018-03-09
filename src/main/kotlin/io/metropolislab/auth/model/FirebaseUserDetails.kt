package io.metropolislab.auth.model

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails

/**
 * Custom User Details class to be used in Spring Security authentication
 */
data class FirebaseUserDetails(val id: String? = null,
                               private val username: String = "",
                               private val password: String = "",
                               val email: String = "",
                               val name: String? = null,
                               val enabled:Boolean = true,
                               val credentialsNonExpired:Boolean = true,
                               val accountNonLocked:Boolean = true,
                               val accountNonExpired:Boolean = true) : UserDetails {

    override fun getUsername() = username

    override fun getPassword() = password

    override fun isCredentialsNonExpired(): Boolean = credentialsNonExpired

    override fun isAccountNonExpired(): Boolean = accountNonExpired

    override fun isAccountNonLocked(): Boolean = accountNonLocked

    override fun getAuthorities(): Collection<GrantedAuthority> = AuthorityUtils.createAuthorityList("USER")

    override fun isEnabled(): Boolean = enabled

    companion object {
        private val serialVersionUID = 1L
    }
}
