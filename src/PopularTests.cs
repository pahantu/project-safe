using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Security;

namespace ProjectSafe {
 public static partial class Tests {
  static string Esc(string text){return SecurityElement.Escape(text);}
  static void GzipProject(string path,string xml){using(var f=File.Create(path))using(var gzip=new GZipStream(f,CompressionMode.Compress))using(var w=new StreamWriter(gzip,Encoding.UTF8))w.Write(xml);}
  static void AddPopularTests(List<Tuple<string,Action>> cases) {
   cases.Add(Tuple.Create("Premiere gzip collects collisions, preserves original and verifies after relocation",(Action)delegate {
    string dir=Folder(),src=Path.Combine(dir,"project"),a=Path.Combine(dir,"A"),b=Path.Combine(dir,"B");Directory.CreateDirectory(src);Directory.CreateDirectory(a);Directory.CreateDirectory(b);
    string one=Path.Combine(a,"Клип 100%.mp4"),two=Path.Combine(b,"Клип 100%.mp4");File.WriteAllText(one,"first asset");File.WriteAllText(two,"second asset");
    string project=Path.Combine(src,"Монтаж.prproj");GzipProject(project,"<PremiereData Version='3'><ActualMediaFilePath>"+Esc(one)+"</ActualMediaFilePath><ProxyFilePath>"+Esc(two)+"</ProxyFilePath></PremiereData>");string hash=Vault.Hash(project);
    Scan scan=Inspect(src);Assert(scan.Files.Count(x=>x.Linked)==2,"external assets missing");Assert(scan.ReadyCount==0,"unvalidated Premiere rewrite advertised");
    string packed=Pack(scan,Path.Combine(dir,"out"));Assert(Vault.Hash(Path.Combine(packed,"Project","Монтаж.prproj"))==hash,"native project changed");
    Directory.Move(src,src+"_unavailable");Directory.Move(a,a+"_unavailable");Directory.Move(b,b+"_unavailable");string moved=Path.Combine(dir,"Перенос");Directory.Move(packed,moved);
    Assert(Vault.Verify(moved,CancellationToken.None,null)==3,"relocation integrity failed");var manifest=Vault.Json().Deserialize<Manifest>(File.ReadAllText(Path.Combine(moved,"manifest.json")));
    Assert(manifest.Files.Where(x=>!x.Path.EndsWith(".prproj")).Select(x=>File.ReadAllText(Vault.SafeChild(moved,x.Path))).OrderBy(x=>x).SequenceEqual(new[]{"first asset","second asset"}),"same-name content lost");Assert(File.ReadAllText(Path.Combine(moved,"Карта исходников.tsv")).Contains(one),"mapping missing");
   }));
   cases.Add(Tuple.Create("Premiere relative and missing media are reported without false Ready",(Action)delegate {
    string src=Folder();File.WriteAllText(Path.Combine(src,"good.wav"),"audio");File.WriteAllText(Path.Combine(src,"p.prproj"),"<PremiereData><RelativePath>good.wav</RelativePath><ActualMediaFilePath>absent.mov</ActualMediaFilePath></PremiereData>");var scan=Inspect(src);Assert(scan.Findings.Any(x=>x.Level=="Не найден"),"missing media not shown");Assert(scan.ReadyCount==0,"incomplete native project marked ready");
   }));
   cases.Add(Tuple.Create("After Effects namespaced AEPX collects footage and preserves binary project",(Action)delegate {
    string dir=Folder(),src=Path.Combine(dir,"src"),image=Path.Combine(dir,"external image.psd");Directory.CreateDirectory(src);File.WriteAllText(image,"PSD fixture");File.WriteAllBytes(Path.Combine(src,"main.aep"),new byte[]{82,73,70,70,0,1,2,3});
    File.WriteAllText(Path.Combine(src,"main.aepx"),"<AfterEffectsProject xmlns='http://www.adobe.com/products/aftereffects'><Fold><fileReference fullpath='"+Esc(image)+"'/></Fold></AfterEffectsProject>");var scan=Inspect(src);Assert(scan.Files.Count(x=>x.Linked)==1,"AEPX namespace path lost");Assert(scan.Findings.Any(x=>x.Message.Contains("Export-AfterEffects")),"binary guidance absent");var packed=Pack(scan,Path.Combine(dir,"out"));Assert(Vault.Hash(Path.Combine(src,"main.aep"))==Vault.Hash(Path.Combine(packed,"Project","main.aep")),"binary changed");
   }));
   cases.Add(Tuple.Create("After Effects native export list collects project, footage and proxy",(Action)delegate {
    string dir=Folder(),src=Path.Combine(dir,"export");Directory.CreateDirectory(src);string project=Path.Combine(dir,"main.aep"),footage=Path.Combine(dir,"main.mov"),proxy=Path.Combine(dir,"proxy.mov");foreach(string path in new[]{project,footage,proxy})File.WriteAllText(path,path);
    File.WriteAllText(Path.Combine(src,"main.psdeps"),"<ProjectSafeDependencies editor='After Effects' version='1'><project path='"+Esc(project)+"'/><file role='footage' path='"+Esc(footage)+"'/><file role='proxy' path='"+Esc(proxy)+"'/><warning>Sequence manual</warning></ProjectSafeDependencies>");var scan=Inspect(src);Assert(scan.Files.Count(x=>x.Linked)==3,"native exported dependencies missing");Assert(scan.Findings.Any(x=>x.Message=="Sequence manual"),"exporter warning lost");Assert(scan.ReadyCount==0,"native export claims automatic relink");
   }));
   cases.Add(Tuple.Create("FCPXML 1.8 and 1.9 collect URI originals and proxies with bare DOCTYPE",(Action)delegate {
    string dir=Folder(),src=Path.Combine(dir,"src");Directory.CreateDirectory(src);string a=Path.Combine(dir,"Лето & 100%.mov"),b=Path.Combine(dir,"proxy.mov");File.WriteAllText(a,"original");File.WriteAllText(b,"proxy");
    File.WriteAllText(Path.Combine(src,"edit.fcpxml"),"<?xml version='1.0'?><!DOCTYPE fcpxml><fcpxml version='1.9'><resources><asset src='"+Esc(new Uri(a).AbsoluteUri)+"'><media-rep kind='proxy-media' src='"+Esc(new Uri(b).AbsoluteUri)+"'/></asset></resources></fcpxml>");var scan=Inspect(src);Assert(scan.Files.Count(x=>x.Linked)==2,"FCPXML src lost");Assert(!scan.Findings.Any(x=>x.Level=="Не найден"||x.Level=="Формат"),"FCPXML parse error");
   }));
   cases.Add(Tuple.Create("Premiere and Resolve exchange XML is detected but ordinary XML stays ordinary",(Action)delegate {
    string dir=Folder();File.WriteAllText(Path.Combine(dir,"sound.wav"),"audio");File.WriteAllText(Path.Combine(dir,"timeline.xml"),"<!DOCTYPE xmeml><xmeml><file><pathurl>sound.wav</pathurl></file></xmeml>");File.WriteAllText(Path.Combine(dir,"settings.xml"),"<config><path>private.txt</path></config>");var scan=Inspect(dir);Assert(scan.Projects==1,"ordinary XML treated as project");Assert(scan.Findings.Any(x=>x.Level=="Сбор связей"),"exchange project not parsed");
   }));
   cases.Add(Tuple.Create("Popular editor network references are refused before file access",(Action)delegate {
    string dir=Folder();File.WriteAllText(Path.Combine(dir,"p.prproj"),"<PremiereData><ActualMediaFilePath>file://not-a-real-server/share/secret.mov</ActualMediaFilePath><FilePath>\\\\not-a-real-server\\share\\secret.mov</FilePath></PremiereData>");var scan=Inspect(dir);Assert(scan.Files.Count==1,"network opened");Assert(scan.Findings.Count(x=>x.Message.StartsWith("Сетевой ресурс"))==2,"network warnings absent");
   }));
   cases.Add(Tuple.Create("Foreign machine paths and sequences are never claimed complete",(Action)delegate {
    string dir=Folder();File.WriteAllText(Path.Combine(dir,"a.fcpxml"),"<fcpxml><asset src='file:///Volumes/Media/clip.mov'/><asset src='https://example.invalid/video.mov'/><asset src='frame%04d.png'/></fcpxml>");var scan=Inspect(dir);Assert(scan.Files.Count==1,"foreign media silently collected");Assert(scan.Findings.Any(x=>x.Message.Contains("другого компьютера")),"macOS path misresolved");Assert(scan.Findings.Any(x=>x.Message.Contains("Последовательность")),"sequence not flagged");Assert(scan.Findings.Any(x=>x.Message.Contains("Внешний адрес")),"URL not flagged");
   }));
   cases.Add(Tuple.Create("External XML entities and wrong document roots are rejected safely",(Action)delegate {
    string dir=Folder();File.WriteAllText(Path.Combine(dir,"entity.aepx"),"<!DOCTYPE AfterEffectsProject [<!ENTITY xxe SYSTEM 'file:///C:/sensitive.txt'>]><AfterEffectsProject>&xxe;</AfterEffectsProject>");File.WriteAllText(Path.Combine(dir,"wrong.prproj"),"<config><FilePath>secret.mov</FilePath></config>");var scan=Inspect(dir);Assert(scan.Files.Count==2,"XML entity accessed");Assert(scan.Findings.Count(x=>x.Level=="Формат")==2,"unsafe root not rejected");
   }));
   cases.Add(Tuple.Create("Corrupt gzip and compressed oversized XML retain originals with clear warnings",(Action)delegate {
    string dir=Folder();File.WriteAllBytes(Path.Combine(dir,"broken.prproj"),new byte[]{31,139,8,0,0});GzipProject(Path.Combine(dir,"large.prproj"),"<PremiereData>"+new string('x',33*1024*1024)+"</PremiereData>");var scan=Inspect(dir);Assert(scan.ReadyCount==0,"invalid project accepted");Assert(scan.Findings.Count(x=>x.Level=="Формат")==2,"gzip bound not enforced");
   }));
   cases.Add(Tuple.Create("Resolve DRP is preserved and native archive guidance is explicit",(Action)delegate {
    string dir=Folder();File.WriteAllBytes(Path.Combine(dir,"movie.drp"),new byte[]{80,75,0,1});var scan=Inspect(dir);Assert(scan.Projects==1,"Resolve not recognized");Assert(scan.Findings.Any(x=>x.Message.Contains("Project Archive")),"Resolve instructions missing");Assert(scan.ReadyCount==0,"opaque DRP marked ready");
   }));
   cases.Add(Tuple.Create("Dependency export unknown version is not accepted as native evidence",(Action)delegate {
    string dir=Folder();File.WriteAllText(Path.Combine(dir,"x.psdeps"),"<ProjectSafeDependencies version='99' editor='After Effects'><file path='secret.mov'/></ProjectSafeDependencies>");var scan=Inspect(dir);Assert(scan.Findings.Any(x=>x.Level=="Формат"),"unknown manifest version accepted");Assert(!scan.Findings.Any(x=>x.Level=="Не найден"),"unknown manifest paths processed");
   }));
  }
 }
}
