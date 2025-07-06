using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Jannesen.PasswordCrypt.Test
{
    [TestClass]
    public class Tests
    {
        [TestMethod]
        public              void    Sha256Verify()
        {
            var pc = new Sha256Crypt();
            Assert.IsTrue(pc.Verify("test", "$5$U243OnZg70/aofTS$k.wkGN6yifo5CzMMGU6C8sojOOc7JR2e.bgFrq1lfs4"));
        }

        [TestMethod]
        public              void    Sha512Verify()
        {
            var pc = new Sha512Crypt();
            Assert.IsTrue(pc.Verify("test", "$6$EI4gpYRl8yKKLxkc$J/I.VumWzCTFB0ogMwh/T1Wo59vGFlUsyM3jDD7A7moPjphmCwInlpiFGyAmO39QDIiwiA6I/JLwd1eJxmXU4/"));
            Assert.IsTrue(pc.Verify("test", "$6$.ndlXBbTysEnOiMY$NqZjW7MPKE/yB.X58fmGGWd52zAs7rG7mbaRAO3joOhhklf.YzmfRyWl6STQF/ya91epZnFTY1z4g6AxLw14m0"));

        }

        [TestMethod]
        public              void    Sha256Create()
        {
            var pc   = new Sha256Crypt();
            var pwd  = "BA$<4V_eCw\"$qpg@r23ip!/EG8gP)£gaOW7*f!2~:J0a0xtrF$";
            var hash = pc.Create(pwd);
            Assert.IsTrue(pc.Verify(pwd, hash));
        }

        [TestMethod]
        public              void    Sha512Create()
        {
            var pc   = new Sha512Crypt();
            var pwd  = "BA$<4V_eCw\"$qpg@r23ip!/EG8gP)£gaOW7*f!2~:J0a0xtrF$";
            var hash = pc.Create(pwd);
            Assert.IsTrue(pc.Verify(pwd, hash));
        }

        [TestMethod]
        public              void    Sha512Speed()
        {
            var pc   = new Sha512Crypt();
            var pwd  = "BA$<4V_eCw\"$qpg@r23ip!/EG8gP)£gaOW7*f!2~:J0a0xtrF$";
            var hash = pc.Create(pwd);

            for (var i = 0 ; i < 100 ; ++i) {
                Assert.IsTrue(pc.Verify(pwd, hash));
            }
        }
    }
}
