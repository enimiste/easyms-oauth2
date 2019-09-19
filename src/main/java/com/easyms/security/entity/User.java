package com.easyms.security.entity;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import lombok.*;
import org.apache.commons.lang3.StringUtils;

import javax.persistence.*;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "roles")
@EqualsAndHashCode(exclude = "roles")
@Entity
@Table(name = "oauth2_users")
public class User {

    @Id
    private String id;

    @Column(unique = true)
    private String login;

    @Column
    private String password;

    @Column
    private boolean enabled;

    @Column
    private Boolean emailValidation = false;

    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.EAGER)
    @JoinTable(name = "oauth2_users_roles",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id", referencedColumnName = "id")}
    )
    private Set<Role> roles = Sets.newHashSet();

    @Column
    private String perimeters;
    @Column
    private String acls;

    public List<String> getPerimetersAsList() {
        return StringUtils.isBlank(perimeters) ? Lists.newArrayList() : Splitter.on(",").trimResults().omitEmptyStrings().splitToList(perimeters);
    }
}
