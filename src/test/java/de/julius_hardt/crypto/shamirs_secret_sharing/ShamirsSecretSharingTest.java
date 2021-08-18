package de.julius_hardt.crypto.shamirs_secret_sharing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.*;

public class ShamirsSecretSharingTest {
    private ShamirsSecretSharing scheme;

    @BeforeEach
    public void setup() {
        scheme = ShamirsSecretSharing.create();
    }

    @Test
    public void testShareNullData() {
        assertNull(scheme.share(10, 9, null));
    }

    @Test
    public void testShareAndReconstructShortMessage() throws InvalidSharesException {
        testShareAndReconstructStringMessage(10, 5, "Hello world!");
    }

    @Test
    public void testShareAndReconstructLongerMessage() throws InvalidSharesException {
        testShareAndReconstructStringMessage(20, 7, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ullamcorper dignissim cras tincidunt lobortis feugiat vivamus. Ut eu sem integer vitae justo. Cras ornare arcu dui vivamus arcu. Ultrices mi tempus imperdiet nulla malesuada pellentesque elit eget. Elementum sagittis vitae et leo duis ut diam quam. Habitasse platea dictumst vestibulum rhoncus est pellentesque elit ullamcorper. Neque convallis a cras semper auctor neque vitae. Netus et malesuada fames ac. Elementum sagittis vitae et leo duis. Non odio euismod lacinia at quis risus sed vulputate. Posuere urna nec tincidunt praesent semper feugiat. Venenatis a condimentum vitae sapien pellentesque habitant. Arcu risus quis varius quam.\n\nQuis enim lobortis scelerisque fermentum. Suspendisse potenti nullam ac tortor vitae purus faucibus. Amet nulla facilisi morbi tempus. Elit scelerisque mauris pellentesque pulvinar pellentesque habitant morbi tristique senectus. Aenean euismod elementum nisi quis eleifend quam adipiscing vitae. Nam libero justo laoreet sit amet cursus sit amet dictum. Sagittis orci a scelerisque purus semper. Sed risus ultricies tristique nulla aliquet enim tortor. Lorem ipsum dolor sit amet consectetur adipiscing elit ut aliquam. Arcu cursus vitae congue mauris rhoncus. Integer quis auctor elit sed vulputate mi sit amet mauris. Sed viverra ipsum nunc aliquet bibendum enim facilisis gravida neque. Neque convallis a cras semper auctor neque vitae tempus quam. Leo vel fringilla est ullamcorper eget. Bibendum est ultricies integer quis auctor elit sed vulputate. Ultrices in iaculis nunc sed augue lacus. Aenean vel elit scelerisque mauris pellentesque.\n\nEget gravida cum sociis natoque penatibus et magnis dis parturient. Diam phasellus vestibulum lorem sed risus. Amet justo donec enim diam. Elementum curabitur vitae nunc sed velit dignissim sodales. Turpis tincidunt id aliquet risus feugiat in ante. Turpis in eu mi bibendum neque egestas congue. In nulla posuere sollicitudin aliquam ultrices. Et leo duis ut diam quam. Eu scelerisque felis imperdiet proin. Nulla malesuada pellentesque elit eget. Suspendisse in est ante in nibh mauris cursus mattis. Ut enim blandit volutpat maecenas volutpat blandit. Dolor sit amet consectetur adipiscing elit ut. Est sit amet facilisis magna etiam tempor. Elit ullamcorper dignissim cras tincidunt lobortis feugiat vivamus at augue.\n\nProin sed libero enim sed faucibus turpis in eu mi. Ornare quam viverra orci sagittis eu volutpat odio facilisis. Nunc mattis enim ut tellus elementum sagittis vitae et leo. In ornare quam viverra orci sagittis eu volutpat odio facilisis. Nunc sed id semper risus in hendrerit gravida. Luctus accumsan tortor posuere ac ut. Quis lectus nulla at volutpat diam ut. Tristique et egestas quis ipsum. Iaculis nunc sed augue lacus viverra. Vel pharetra vel turpis nunc eget lorem dolor. A diam maecenas sed enim ut sem. Tristique risus nec feugiat in fermentum posuere urna nec tincidunt.\n\nConvallis posuere morbi leo urna. Pulvinar elementum integer enim neque volutpat ac tincidunt vitae. Nullam non nisi est sit. A condimentum vitae sapien pellentesque. Cras semper auctor neque vitae tempus quam pellentesque nec nam. Elementum tempus egestas sed sed risus pretium quam vulputate dignissim. Ut sem nulla pharetra diam sit amet nisl. Sed enim ut sem viverra aliquet eget sit amet. Sit amet nulla facilisi morbi tempus iaculis urna id volutpat. Suspendisse faucibus interdum posuere lorem. Posuere sollicitudin aliquam ultrices sagittis orci a scelerisque purus. Massa tincidunt dui ut ornare lectus sit amet est placerat. Consectetur adipiscing elit pellentesque habitant morbi tristique senectus. Nisi scelerisque eu ultrices vitae auctor. Bibendum est ultricies integer quis auctor elit sed vulputate mi. Feugiat in ante metus dictum at tempor. Convallis convallis tellus id interdum velit laoreet id donec.");
    }

    @Test
    public void testShareAndReconstructUnalignedMessageWithMultipleBlocks() throws InvalidSharesException {
        testShareAndReconstructStringMessage(181, 98, getRandomStringOfUppercaseLetters(3 * 64 - 7));
        testShareAndReconstructStringMessage(101, 51, getRandomStringOfUppercaseLetters(3 * 64 - 7));
        testShareAndReconstructStringMessage(93, 27, getRandomStringOfUppercaseLetters(3 * 64 - 7));
    }

    @Test
    public void testShareAndReconstructUnalignedMessageWithOnlyOneBlock() throws InvalidSharesException {
        testShareAndReconstructStringMessage(40, 36, getRandomStringOfUppercaseLetters(64 - 37));
        testShareAndReconstructStringMessage(175, 87, getRandomStringOfUppercaseLetters(64 - 37));
        testShareAndReconstructStringMessage(192, 89, getRandomStringOfUppercaseLetters(64 - 37));
    }

    @Test
    public void testShareAndReconstructAlignedMessageWithWholePaddingBlock() throws InvalidSharesException {
        testShareAndReconstructStringMessage(40, 36, getRandomStringOfUppercaseLetters(64));
        testShareAndReconstructStringMessage(46, 3, getRandomStringOfUppercaseLetters(2 * 64));
        testShareAndReconstructStringMessage(83, 12, getRandomStringOfUppercaseLetters(3 * 64));
    }

    @Test
    public void testReconstructThrowsWhenOneShareIsNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[][] invalidInput = new byte[3][];
            invalidInput[0] = new byte[113];
            invalidInput[1] = null;
            invalidInput[2] = new byte[113];
            scheme.reconstruct(invalidInput);
        });
    }

    @Test
    public void testReconstructThrowsWhenSharesHaveDifferentLengths() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[][] invalidInput = new byte[4][];
            invalidInput[0] = new byte[113];
            invalidInput[1] = new byte[113];
            invalidInput[2] = new byte[113];
            invalidInput[3] = new byte[114];
            scheme.reconstruct(invalidInput);
        });
    }

    @Test
    public void testReconstructThrowsWhenSharesAreTooSmall() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[][] invalidInput = new byte[4][];
            invalidInput[0] = new byte[112];
            invalidInput[1] = new byte[112];
            invalidInput[2] = new byte[112];
            invalidInput[3] = new byte[112];
            scheme.reconstruct(invalidInput);
        });
    }

    @Test
    public void testReconstructThrowsWhenSharesAreTooBig() {
        assertThrows(IllegalArgumentException.class, () -> {
            byte[][] invalidInput = new byte[4][];
            invalidInput[0] = new byte[114];
            invalidInput[1] = new byte[114];
            invalidInput[2] = new byte[114];
            invalidInput[3] = new byte[114];
            scheme.reconstruct(invalidInput);
        });
    }

    private void testShareAndReconstruct(int n, int t, byte[] data) throws InvalidSharesException {
        byte[][] generatedShares = scheme.share(n, t, data);
        Collections.shuffle(Arrays.asList(generatedShares));
        byte[][] sharesSelectedForReconstruction = new byte[t][generatedShares[0].length];
        System.arraycopy(generatedShares, 0, sharesSelectedForReconstruction, 0, t);
        byte[] actualResult = scheme.reconstruct(sharesSelectedForReconstruction);
        assertArrayEquals(data, actualResult);
    }

    private void testShareAndReconstructStringMessage(int n, int t, String message) throws InvalidSharesException {
        testShareAndReconstruct(n, t, message.getBytes());
    }

    private String getRandomStringOfUppercaseLetters(int length) {
        StringBuilder sb = new StringBuilder();
        Random random = ThreadLocalRandom.current();
        for (int i = 0; i < length; i++) {
            sb.append((char)('A' + random.nextInt(26)));
        }
        return sb.toString();
    }
}
