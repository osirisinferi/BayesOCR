#*************************************************************************
# Bayes OCR Plugin, version 0.1
#*************************************************************************
# Copyright 2007 P.R.A. Group - D.I.E.E. - University of Cagliari (ITA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#*************************************************************************

package Mail::SpamAssassin::Plugin::BayesOCR_PLG;

use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw (Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
   my ( $class, $mailsa ) = @_;
   $class = ref($class) || $class;
   my $self = $class->SUPER::new($mailsa);
   bless( $self, $class );
   dbg("PLG-BayesOCR:: new:: register_eval_rule");

   $self->register_eval_rule("BayesOCR_check");
   $self->{'imgTxt_classifierOut'} = -1;
   $self->{'imgTxt_tagmsg'} = ""; #msg to be saved in e-mail tag when $self->{'imgTxt_classifierOut'} <= 0

   return $self;
}

#===========================================================================
#===========================================================================

sub check_start{
    # Called before eval rule
    my ( $self, $pms ) = @_;
    dbg("PLG-BayesOCR:: check_start:: init score");

    #Init outNB_imgTxt
    $self->{'imgTxt_classifierOut'} = -1;
    $self->{'imgTxt_tagmsg'} = "";
}

sub isValidUser{
    my ($pms) = @_;
    my $username = $pms->{main}->{username};
    dbg("PLG-BayesOCR:: isValidUser:: Username: $username");

    return 1;
}


sub BayesOCR_check {
    # BayesOCR_check(thr)
    # Return an hit when (outNB > thr)
    # The score is computed as (weigth * outNB)
    #
    my ($self, $pms, $unused, $thrL, $thrH) = @_;
    my $plgRuleName = $pms->get_current_eval_rule_name();

    #if( isValidUser($pms) == 0) { return 0; }

    dbg("PLG-BayesOCR:: BayesOCR_check :: Rule: $plgRuleName");
    dbg("PLG-BayesOCR:: BayesOCR_check ::  thr: ($thrH, $thrL)");


    if($self->{'imgTxt_classifierOut'} < 0)
    {
        #Output
        if( $self->imageSpam_OCRTextProcessing($pms ) )
        {
            $self->{'imgTxt_tagmsg'} = $self->{'imgTxt_classifierOut'};
        }

        dbg("PLG-BayesOCR:: BayesOCR_check:: Write Mail Header\n\n");
        $pms->set_tag ("PLGBAYESOCROUT", $self->{'imgTxt_tagmsg'} );
    }
    my $resHit = ($self->{'imgTxt_classifierOut'} > $thrL) && ($self->{'imgTxt_classifierOut'} <= $thrH );

    return $resHit;
}

1;

#===========================================================================

sub imageSpam_OCRTextProcessing
# boolen $self->imageSpam_OCRTextProcessing($pms)
#
# imageSpam processing by image's text analisys with SA's NaiveBayes
# return 1 : (sucess) image's text has beeen extract and processed by NB
# return 0 : (failed) no images, no text, no NB.
{
    my ( $self, $pms ) = @_;
    # $self :: Obj Plugin
    # $pms ::  Obj Mail::SpamAssassin::PerMsgStatus
    # $pms->{msg} :: message of class Mail::SpamAssassin::Message
    $self->{'imgTxt_classifierOut'} = 0;

    dbg("PLG-BayesOCR:: imageSpam_OCRTextProcessing:: Check for Attached Images");

    #================================
    # Image extraction
    #================================
    my ($imgTextOcr, $numImages) = imageTextExtractionFromMSG($pms->{msg});

    if($numImages == 0)
    {
        $self->{'imgTxt_tagmsg'} = "0.0 (No images found)";
        return 0;
    }

    my $numWord = 0;
    while($imgTextOcr =~ /[a-z]{3,}/gi)
    {
        $numWord++;
    }

    dbg("PLG-BayesOCR:: imageTextExtractionFromMSG:: $numWord words (3+ chars) recognised");

    if($numWord <= 3)
    {
        $self->{'imgTxt_tagmsg'} = "0.0 (No usefull text found)";
        return 0;
    }

    #================================
    # Classifier's output estimation
    #================================
    #compute and save score
    my $res = $self->imageTextClassifierOutEstimation($pms, $imgTextOcr);

    return $res;
}

#===========================================================================

sub imageTextClassifierOutEstimation
# $classifierOutput = $self->imageTextClassifierOutEstimation($pms, $imgTextOcr)
# Classify the text of "$imgTextOcr" by the predefinited classifier.
# Classifier's output is saved in $self->{'imgTxt_classifierOut'}
{
    my ( $self, $pms, $imgTextOcr) = @_;
    #================================
    # creation of msg with image's text
    #================================
    my $mailraw = createMSGFromText($pms, $imgTextOcr);
    my $msgTmp = $pms->{main}->parse($mailraw,1);

    #================================
    # Score estimation
    #================================
    dbg("PLG-BayesOCR:: imageTextClassifierOutEstimation:: Compute score with trained NaiveBayes");
    my $pmsTMP = new Mail::SpamAssassin::PerMsgStatus($pms->{main}, $msgTmp);
    my $nbSA = $pms->{main}->{bayes_scanner};
    #my $nbSA = new Mail::SpamAssassin::Bayes ($pms->{main});

    if( $nbSA->is_scan_available() == 0)
    {
        dbg("PLG-BayesOCR:: imageTextClassifierOutEstimation: NB scan not available");
        $self->{'imgTxt_tagmsg'} = "0.0 (NaiveBayes scan not available)";
        return 0;
    }

    my $outNB = $nbSA->scan($pmsTMP, $msgTmp);
    $self->{'imgTxt_classifierOut'} = sprintf("%0.3f", $outNB);

    dbg("PLG-BayesOCR:: imageTextClassifierOutEstimation:: classifier's out = $self->{'imgTxt_classifierOut'}" );

    return 1;
}

#===========================================================================

sub imageTextExtractionFromMSG
# ($imgTextOcr, $numImages) = imageTextExtractionFromMSG($msg)
# Extract the text from all attached images
# Return all text anche the number of attached images
{
    my $msg = $_[0];

    dbg("PLG-BayesOCR:: imageTextExtractionFromMSG:: Extract & Convert Images");

    my @mimeStr = ("image/*", "img/*");
    my @tmpImgFile;
    my $num=0;

    my $imgTextOcr = "";

    foreach (@mimeStr)
    {
        # Search all attach with current MIME
        my @img_parts =  $msg->find_parts($_);
        for (my $i=0; $i <= $#img_parts; $i++)
        {
            my $imagestream = $img_parts[$i]->decode(1048000);  # ~ 1 MB
            $imgTextOcr = join $imgTextOcr,  imageTextExtractionByOCR($imagestream), "\n";

            $num++;
        }
    }

    dbg("PLG-BayesOCR:: imageTextExtractionFromMSG:: $num images extracted");
    return ($imgTextOcr, $num);
}

#===========================================================================

sub imageTextExtractionByOCR
# $textOut = imageTextExtractionByOCR( $imagestream )
# Text extraction from imge file "" by OCR engine
{
    my $imagestream = $_[0];
    my $imagelen = length($imagestream) / 1024;
    my $tmpDir = "/tmp"; #Get tmp dir
    my $tmpFile = "$tmpDir/sa_bayesOCR_tmpImg.$$";

    # Zooming small images could improve OCR accuracy

    # Byte Check
    # > 1000K => no OCR
    # < 15K   =>  OCR + zoom 4X
    #  else   => Check resolution

    # Check resolution
    #    res > 1400x1050          => no OCR
    # 1024x768 <= res < 1400x1050 => OCR  (no zoom)
    #  800x600 <= res < 1024x768  => OCR + zoom 2X
    #    res < 800x600  => OCR + zoom 4X

    #if ($imagelen > 1000)
    #{
    #    dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Skip, image size = $imagelen");
    #    return "";
    #}

    open (FILE, ">$tmpFile.raw") or return "";
    print FILE "$imagestream\n";
    close FILE;

    #my $convertOPT = "";
    #my $imageIdentifyTxt = "";
    #if($imagelen < 20 )
    #{
    #    dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Enable zoom 4X");
    #    $convertOPT = "-sample 400% -density 280";
    #}
    #else
    #{
    #    dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Check image dim");

        # check WxH
    #    open  EXEFH, "identify -quiet -ping $tmpFile.raw |";
    #    $imageIdentifyTxt = join "", <EXEFH>;
    #    close EXEFH;

    #    if( $imageIdentifyTxt =~ s/\s(\d*)x(\d*)\s//i )
    #    {
    #        my $size1 = $1;
    #        my $size2 = $2;

    #        if($size1 * $size2  > 1400*1050 && $size1 > 1280 && $size2  > 1024)
    #        {
    #            dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Skip, image dim = $size1 x $size2");
    #            unlink "$tmpFile.raw";
    #            return "";
    #        }

    #        if( $size1 * $size2  < 800*600)
    #        {
    #            dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Enable zoom 4X");
    #            $convertOPT = "-sample 400% -density 280";
    #        }
    #        elsif( $size1 * $size2  < 1024*768)
    #        {
    #            dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Enable zoom 2X");
    #            $convertOPT = "-sample 200% -density 280";
    #        }
    #    }
    #}

    dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: OCR");
    # -append  :: concatenate image i layers
    # -flatten :: fuse layers
    # -density :: set dpi

    #my $exstatus = system("convert $tmpFile.raw -append -flatten $convertOPT $tmpFile.pnm");
    #if($exstatus != 0)
    #{
    #    dbg("PLG-BayesOCR:: imageTextExtractionByOCR:: Convert ERROR!!");
    #    open  EXEFH, "identify -verbose -strip $tmpFile.raw |";
    #    $imageIdentifyTxt = join "", <EXEFH>;
    #    close EXEFH;

    #    my $timenow = localtime time;
    #    open (FILE, ">>$tmpDir/sa_bayesOCR.log");

    #    print FILE "\n#--------------------------------\n";
    #    print FILE "  $timenow\n";
    #    print FILE "  Convert processing error";
    #    print FILE "\n#--------------------------------\n\n";

    #    print FILE "Stream size (kb): $imagelen\n";
    #    print FILE "Identify output: \n$imageIdentifyTxt\n";
    #    close FILE;

    #    unlink "$tmpFile.raw";
    #    return "";
    #}

    open EXEFH, "tesseract $tmpFile.raw - -l nld+eng+enm |";
    my $textOut = join "", <EXEFH>;
    close EXEFH;

    unlink "$tmpFile.raw";
    #unlink "$tmpFile.pnm";

    return $textOut;
}

#===========================================================================

sub createMSGFromText
# msg = createMSGFromText(@img_ocrText)
{
    my ($pms, $ocrText) = @_;
    dbg("PLG-BayesOCR: createMSGFromText:: Make temp email with OCR's text");

    my $subject = "";
    my $date = $pms->{msg}->get_pristine_header("Date");
    my $from = $pms->{msg}->get_pristine_header("From");
    my $to = $pms->{msg}->get_pristine_header("To");
    my $msgID = $pms->{msg}->get_pristine_header("Message-ID");

    my $mailraw = "Subject: $subject\nMessage-ID: $msgID\nDate: $date\nFrom: $from\nTo: $to\nMIME-Version: 1.0\nContent-Type: text/plain; charset=us-ascii\nContent-Transfer-Encoding: 7bit\n\n$ocrText\n";

    return $mailraw
}



