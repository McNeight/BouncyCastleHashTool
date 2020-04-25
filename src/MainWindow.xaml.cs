// <copyright file="MainWindow.xaml.cs" company="Neil McNeight">
// Copyright © 2020 Neil McNeight.
// All rights reserved. Licensed under the MIT license.
// See LICENSE file in the project root for full license information.
// </copyright>

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

using Org.BouncyCastle.Crypto.Digests;

namespace BouncyCastleHashTool
{
    [ValueConversion(typeof(bool?), typeof(CharacterCasing))]
    public class BoolToCharacterCasingConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((bool?)value == true) ? CharacterCasing.Upper : CharacterCasing.Lower;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // Don't need any convert back
            return null;
        }
    }

    [ValueConversion(typeof(string), typeof(string))]
    public class LowerCaseToUpperCaseConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value.ToString().ToUpperInvariant();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value.ToString().ToLowerInvariant();
        }
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml.
    /// </summary>
    public partial class MainWindow : Window
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// </summary>
        public MainWindow()
        {
            this.InitializeComponent();
        }

        private void btnSelect_Click(object sender, RoutedEventArgs e)
        {
            string filename_ext;
            string filename;

            // Create OpenFileDialog
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                // Set filter for file extension and default file extension.
                Filter = "All Files (*.*)|*.*",
            };

            // Display OpenFileDialog by calling ShowDialog method.
            var result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox.
            if (result.HasValue && result.Value)
            {
                // Open document
                filename_ext = dlg.FileName;
                filename = Path.GetDirectoryName(filename_ext) + @"\" + Path.GetFileNameWithoutExtension(filename_ext);
                this.tbFileName.Text = filename_ext;

                if (File.Exists(filename_ext + ".sfv"))
                {
                    this.cmpCrc32.Text = this.ProcessSfvFile(filename_ext + ".sfv");
                }
                else if (File.Exists(filename + ".sfv"))
                {
                    this.cmpCrc32.Text = this.ProcessSfvFile(filename + ".sfv");
                }

                if (File.Exists(filename_ext + ".md5"))
                {
                    this.cmpMd5.Text = this.ProcessHashFile(filename_ext + ".md5");
                }
                else if (File.Exists(filename + ".md5"))
                {
                    this.cmpMd5.Text = this.ProcessHashFile(filename + ".md5");
                }

                if (File.Exists(filename_ext + ".sha1"))
                {
                    this.cmpSha1.Text = this.ProcessHashFile(filename_ext + ".sha1");
                }
                else if (File.Exists(filename + ".sha1"))
                {
                    this.cmpSha1.Text = this.ProcessHashFile(filename + ".sha1");
                }

                if (File.Exists(filename_ext + ".sha256"))
                {
                    this.cmpSha256.Text = this.ProcessHashFile(filename_ext + ".sha256");
                }
                else if (File.Exists(filename + ".sha256"))
                {
                    this.cmpSha256.Text = this.ProcessHashFile(filename + ".sha256");
                }
            }
        }

        private string ProcessSfvFile(string hashFilename)
        {
            var lines = File.ReadLines(hashFilename);
            var searchString = Path.GetFileNameWithoutExtension(hashFilename);

            foreach (var line in lines)
            {
                var groups = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);

                if (groups.Length == 2)
                {
                    if (groups[0].Contains(searchString, StringComparison.CurrentCulture))
                    {
                        return groups[1];
                    }
                }
            }

            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "{0} was not found within {1}", searchString, hashFilename), nameof(hashFilename));
        }

        private string ProcessHashFile(string hashFilename)
        {
            var lines = File.ReadLines(hashFilename);
            var searchString = Path.GetFileNameWithoutExtension(hashFilename);

            foreach (var line in lines)
            {
                var groups = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);

                if (groups.Length == 2)
                {
                    if (groups[1].Contains(searchString, StringComparison.CurrentCulture))
                    {
                        return groups[0];
                    }
                }
            }

            throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "{0} was not found within {1}", searchString, hashFilename), nameof(hashFilename));
        }

        private void btnCalculate_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(this.tbFileName.Text))
            {
                return;
            }

            var digestList = new List<ValueTuple<Org.BouncyCastle.Crypto.IDigest, TextBox, byte[]>>();

            if (this.cbBlake2b.IsChecked == true)
            {
                var blake2b = (digest: new Blake2bDigest(), tb: this.tbBlake2b, result: new byte[new Blake2bDigest().GetDigestSize()]);
                digestList.Add(blake2b);
            }

            if (this.cbBlake2s.IsChecked == true)
            {
                var blake2s = (digest: new Blake2sDigest(), tb: this.tbBlake2s, result: new byte[new Blake2sDigest().GetDigestSize()]);
                digestList.Add(blake2s);
            }

            if (this.cbDstu7564_256.IsChecked == true)
            {
                var dstu7564_256 = (digest: new Dstu7564Digest(256), tb: this.tbDstu7564_256, result: new byte[new Dstu7564Digest(256).GetDigestSize()]);
                digestList.Add(dstu7564_256);
            }

            if (this.cbDstu7564_384.IsChecked == true)
            {
                var dstu7564_384 = (digest: new Dstu7564Digest(384), tb: this.tbDstu7564_384, result: new byte[new Dstu7564Digest(384).GetDigestSize()]);
                digestList.Add(dstu7564_384);
            }

            if (this.cbDstu7564_512.IsChecked == true)
            {
                var dstu7564_512 = (digest: new Dstu7564Digest(512), tb: this.tbDstu7564_512, result: new byte[new Dstu7564Digest(512).GetDigestSize()]);
                digestList.Add(dstu7564_512);
            }

            if (this.cbGost3411.IsChecked == true)
            {
                var gost = (digest: new Gost3411Digest(), tb: this.tbGost3411, result: new byte[new Gost3411Digest().GetDigestSize()]);
                digestList.Add(gost);
            }

            if (this.cbKeccak.IsChecked == true)
            {
                var keccak = (digest: new KeccakDigest(), tb: this.tbKeccak, result: new byte[new KeccakDigest().GetDigestSize()]);
                digestList.Add(keccak);
            }

            if (this.cbMd2.IsChecked == true)
            {
                var md2 = (digest: new MD2Digest(), tb: this.tbMd2, result: new byte[new MD2Digest().GetDigestSize()]);
                digestList.Add(md2);
            }

            if (this.cbMd4.IsChecked == true)
            {
                var md4 = (digest: new MD4Digest(), tb: this.tbMd4, result: new byte[new MD4Digest().GetDigestSize()]);
                digestList.Add(md4);
            }

            if (this.cbMd5.IsChecked == true)
            {
                var md5 = (digest: new MD5Digest(), tb: this.tbMd5, result: new byte[new MD5Digest().GetDigestSize()]);
                digestList.Add(md5);
            }

            if (this.cbRipemd128.IsChecked == true)
            {
                var ripemd128 = (digest: new RipeMD128Digest(), tb: this.tbRipemd128, result: new byte[new RipeMD128Digest().GetDigestSize()]);
                digestList.Add(ripemd128);
            }

            if (this.cbRipemd160.IsChecked == true)
            {
                var ripemd160 = (digest: new RipeMD160Digest(), tb: this.tbRipemd160, result: new byte[new RipeMD160Digest().GetDigestSize()]);
                digestList.Add(ripemd160);
            }

            if (this.cbRipemd256.IsChecked == true)
            {
                var ripemd256 = (digest: new RipeMD256Digest(), tb: this.tbRipemd256, result: new byte[new RipeMD256Digest().GetDigestSize()]);
                digestList.Add(ripemd256);
            }

            if (this.cbRipemd320.IsChecked == true)
            {
                var ripemd320 = (digest: new RipeMD320Digest(), tb: this.tbRipemd320, result: new byte[new RipeMD320Digest().GetDigestSize()]);
                digestList.Add(ripemd320);
            }

            if (this.cbSha1.IsChecked == true)
            {
                var sha1 = (digest: new Sha1Digest(), tb: this.tbSha1, result: new byte[new Sha1Digest().GetDigestSize()]);
                digestList.Add(sha1);
            }

            if (this.cbSha224.IsChecked == true)
            {
                var sha224 = (digest: new Sha224Digest(), tb: this.tbSha224, result: new byte[new Sha224Digest().GetDigestSize()]);
                digestList.Add(sha224);
            }

            if (this.cbSha256.IsChecked == true)
            {
                var sha256 = (digest: new Sha256Digest(), tb: this.tbSha256, result: new byte[new Sha256Digest().GetDigestSize()]);
                digestList.Add(sha256);
            }

            if (this.cbSha384.IsChecked == true)
            {
                var sha384 = (digest: new Sha384Digest(), tb: this.tbSha384, result: new byte[new Sha384Digest().GetDigestSize()]);
                digestList.Add(sha384);
            }

            if (this.cbSha512.IsChecked == true)
            {
                var sha512 = (digest: new Sha512Digest(), tb: this.tbSha512, result: new byte[new Sha512Digest().GetDigestSize()]);
                digestList.Add(sha512);
            }

            if (this.cbSha3.IsChecked == true)
            {
                var sha3 = (digest: new Sha3Digest(), tb: this.tbSha3, result: new byte[new Sha3Digest().GetDigestSize()]);
                digestList.Add(sha3);
            }

            if (this.cbSm3.IsChecked == true)
            {
                var sm3 = (digest: new SM3Digest(), tb: this.tbSm3, result: new byte[new SM3Digest().GetDigestSize()]);
                digestList.Add(sm3);
            }

            if (this.cbShake.IsChecked == true)
            {
                var shake = (digest: new ShakeDigest(), tb: this.tbShake, result: new byte[new ShakeDigest().GetDigestSize()]);
                digestList.Add(shake);
            }

            if (this.cbTiger.IsChecked == true)
            {
                var tiger = (digest: new TigerDigest(), tb: this.tbTiger, result: new byte[new TigerDigest().GetDigestSize()]);
                digestList.Add(tiger);
            }

            if (this.cbWhirlpool.IsChecked == true)
            {
                var whirlpool = (digest: new WhirlpoolDigest(), tb: this.tbWhirlpool, result: new byte[new WhirlpoolDigest().GetDigestSize()]);
                digestList.Add(whirlpool);
            }

            using var hashStream = File.ReadAllBytesAsync(this.tbFileName.Text);
            var data = hashStream.Result;

            foreach (var i in digestList)
            {
                i.Item1.BlockUpdate(data, 0, data.Length);
                i.Item1.DoFinal(i.Item3, 0);

                // Create a new Stringbuilder to collect the bytes
                // and create a string.
                var sBuilder = new StringBuilder();

                // Loop through each byte of the hashed data
                // and format each one as a hexadecimal string.
                for (var j = 0; j < i.Item3.Length; j++)
                {
                    if (this.rbUpper.IsChecked == true)
                    {
                        sBuilder.Append(i.Item3[j].ToString("X2", CultureInfo.CurrentCulture));
                    }
                    else
                    {
                        sBuilder.Append(i.Item3[j].ToString("x2", CultureInfo.CurrentCulture));
                    }
                }

                // Finally, post the string into the TextBox
                i.Item2.Text = sBuilder.ToString();
            }
        }

        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            foreach (UIElement ui in this.gridResults.Children)
            {
                if (ui.GetType().ToString().EndsWith("TextBox", StringComparison.InvariantCulture))
                {
                    ((TextBox)ui).Text = string.Empty;
                }
            }
        }

        private void btnAllDigests_Click(object sender, RoutedEventArgs e)
        {
            foreach (UIElement ui in this.gridDigest.Children)
            {
                if (ui.GetType().ToString().EndsWith("StackPanel", StringComparison.InvariantCulture))
                {
                    foreach (UIElement ui2 in ((StackPanel)ui).Children)
                    {
                        if (ui2.GetType().ToString().EndsWith("CheckBox", StringComparison.InvariantCulture))
                        {
                            ((CheckBox)ui2).IsChecked = true;
                        }
                    }
                }
            }
        }

        private void cmp_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Get name of TextBox minus 'cmp' prefix
            var imya = ((TextBox)sender).Name.Substring(3);

            // Get the results text box as well as the label
            var resultsTextBox = LogicalTreeHelper.FindLogicalNode(this.gridResults, "tb" + imya);
            var validationLabel = LogicalTreeHelper.FindLogicalNode(this.gridResults, "lbl" + imya);

            // Get string to compare against results
            string compare;
            if (this.rbUpper.IsChecked == true)
            {
                compare = ((TextBox)sender).Text.Trim().ToUpperInvariant();
            }
            else
            {
                compare = ((TextBox)sender).Text.Trim().ToLowerInvariant();
            }

            // Get results
            string results;
            if (this.rbUpper.IsChecked == true)
            {
                results = ((TextBox)resultsTextBox).Text.Trim().ToUpperInvariant();
            }
            else
            {
                results = ((TextBox)resultsTextBox).Text.Trim().ToLowerInvariant();
            }

            // Check for null strings
            if (string.IsNullOrEmpty(compare) || string.IsNullOrEmpty(results))
            {
                ((Label)validationLabel).Background = System.Windows.Media.Brushes.Transparent;
            }
            else if (compare == results)
            {
                ((Label)validationLabel).Background = System.Windows.Media.Brushes.Green;
            }
            else
            {
                ((Label)validationLabel).Background = System.Windows.Media.Brushes.Red;
            }
        }
    }
}
