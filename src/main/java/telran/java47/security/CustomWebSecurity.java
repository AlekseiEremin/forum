package telran.java47.security;

import java.time.LocalDate;

import javax.xml.crypto.Data;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;
import telran.java47.post.dao.PostRepository;
import telran.java47.post.model.Post;

@Service("customSecurity")
@RequiredArgsConstructor
public class CustomWebSecurity {
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;

	public boolean checkPostAuthor(String posiId, String userName) {
		Post post = postRepository.findById(posiId).orElse(null);
		return post != null && userName.equalsIgnoreCase(post.getAuthor());
	}

	public boolean checkPasswordTime(String username) {
		UserAccount user = userAccountRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
		return user.getPasswordTime().isAfter(LocalDate.now());
	}
}
