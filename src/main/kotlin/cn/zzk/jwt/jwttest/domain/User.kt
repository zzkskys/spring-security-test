package cn.zzk.jwt.jwttest.domain

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.*
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.Id

@Entity
open class User(
        private var username: String,

        private var password: String
) : UserDetails {

    @Id
    @Column(length = 36)
    val id: String = UUID.randomUUID().toString()


    override fun getAuthorities(): MutableList<SimpleGrantedAuthority> {
        return mutableListOf(SimpleGrantedAuthority("ADMIN"), SimpleGrantedAuthority("USER"))
    }

    override fun isEnabled(): Boolean = true

    override fun isCredentialsNonExpired(): Boolean = true

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true

    override fun getPassword(): String = password

    override fun getUsername(): String = username

    open fun setAuthorities(authorities: Collection<GrantedAuthority>) {
        //nothing to do
    }
//
//    open fun setUsername(username: String) {
//        this.username = username
//    }

    open fun setPassword(password: String) {
        this.password = password
    }


}

interface UserRepo : JpaRepository<User, String> {

    @Query("select u from User u where u.username = ?1")
    fun findByName(name: String): User?
}